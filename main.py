# coding=utf-8

from os.path import exists
import json
import random
import smtplib
from email.mime.text import MIMEText
import base64
from cryptography.fernet import Fernet
from getpass import getpass

filename = "spegial-secret-santa.json"


def load_data_from_file():
    if exists(filename):
        with open(filename, "r") as f:
            contents = f.read()
            print("Dati caricati da file")
            return json.loads(contents)

    print("Non ho trovato dati salvati precedentemente")

    key = Fernet.generate_key()

    return {
        'players': [],
        'rules': [],
        'extractions': [],
        'key': key.decode('utf-8')
    }


def save_data_to_file(content):
    with open(filename, "w") as f:
        f.write(json.dumps(content, sort_keys=True, indent=4))
        print("File salvato")


def add_user(content):
    name = input("Inserisci nome:")
    email = input("Inserisci email:")

    for player in content['players']:
        if name == player['name']:
            print("Nome già utilizzato")
            return

        if email == player['email']:
            print("Indirizzo email già utilizzato")
            return

    id = 0
    for player in content['players']:
        id = max(id, player['id'])

    id = id + 1

    content['players'].append({
        'id': id,
        'name': name,
        'email': email
    })


def show_players(content):
    for player in content['players']:
        print(player['id'], player['name'], player['email'])

        has_rules = False
        for rule in content['rules']:
            if rule['player_from'] == player['id']:
                player_to = find_player_by_id(content, rule['player_to'])
                print("\tNon fa il regalo a:", player_to['name'])
                has_rules = True

        if not has_rules:
            print("\tFa il regalo a tutti")


def find_player_by_id(content, id):
    for player in content['players']:
        if player['id'] == id:
            return player

    print("Non ho trovato nessun giocatore con id", id)
    return None


def find_player_by_name(content, name):
    for player in content['players']:
        if player['name'] == name:
            return player

    print("Non ho trovato nessun giocatore con nome", name)
    return None


def add_rule(content):
    name = input("Scegli giocatore:")
    player = find_player_by_name(content, name)
    if player is None:
        return

    present_to_name = input("Inserisci giocatore verso cui scrivere la regola:")
    player_present = find_player_by_name(content, present_to_name)

    if player_present is None:
        return

    existing_rule = None
    for rule in content['rules']:
        if rule['player_from'] == player['id'] and rule['player_to'] == player_present['id']:
            existing_rule = rule
            break

    if existing_rule is not None:
        sn = input("Trovata regola tra i giocatori selezionati. Vuoi eliminarla? [S/N]")
        if sn == "S":
            content['rules'].remove(existing_rule)
            print("Regola eliminata")
    else:
        print("Sto per inserire la regola: ", player['name'], "non fa il regalo a: ", player_present['name'])
        sn = input("Procedo? [S/N]")
        if sn == "S":
            content['rules'].append({
                'player_from': player['id'],
                'player_to': player_present['id']
            })


def extraction(content):
    if len(content['players']) <= 1:
        print("Aggiungi più giocatori per eseguire l'estrazione!")
        return

    ok = False
    players_shuffled = random.sample(content['players'], len(content['players']))

    while not ok:
        ok = True
        players_shuffled = random.sample(content['players'], len(content['players']))

        for i in range(0, len(players_shuffled)):
            present_from_id = content['players'][i]['id']
            present_to_id = players_shuffled[i]['id']

            if present_from_id == present_to_id:
                ok = False

            for rule in content['rules']:
                if rule['player_from'] == present_from_id and rule['player_to'] == present_to_id:
                    ok = False

    result = []
    for i in range(0, len(players_shuffled)):
        present_from_id = content['players'][i]['id']
        present_to_id = players_shuffled[i]['id']

        result.append({
            'present_from_id': present_from_id,
            'present_to_id': present_to_id
        })

    key = content['key'].encode('utf-8')
    fernet = Fernet(key)

    encoded_extraction = fernet.encrypt(json.dumps(result).encode())

    extraction_id = 0
    for extr in content['extractions']:
        extraction_id = max(extraction_id, extr['id'])

    extraction_id = extraction_id + 1

    content['extractions'].append({
        'id': extraction_id,
        'extraction': encoded_extraction.decode('utf-8')
    })

    print("Estrazione ok con id ", extraction_id, encoded_extraction)


def send_email(content):
    extraction_id = int(input("Scegli numero di estrazione: "))
    extr = None
    for extraction in content['extractions']:
        if extraction['id'] == extraction_id:
            extr = extraction
            break

    if extr is None:
        print("Nessuna estrazione trovata")
        return

    id = int(input("Scegli giocatore:"))
    player = find_player_by_id(content, id)

    if player is None:
        return

    sender = input("Indirizzo email di invio: ")
    password = getpass()

    send_email_to_player(content, player, extr, sender, password)


def send_email_all(content):
    extraction_id = int(input("Scegli numero di estrazione: "))
    extr = None
    for extraction in content['extractions']:
        if extraction['id'] == extraction_id:
            extr = extraction
            break

    if extr is None:
        print("Nessuna estrazione trovata")
        return

    sender = input("Indirizzo email di invio: ")
    password = getpass("Inserisci password email per l'invio: ")

    for player in content['players']:
        send_email_to_player(content, player, extr, sender, password)


def send_email_to_player(content, player, extr, sender, password):
    key = content['key'].encode('utf-8')
    fernet = Fernet(key)

    decrypted_extraction = json.loads(fernet.decrypt(extr['extraction']).decode())

    player_to = None

    for assignment in decrypted_extraction:
        if assignment['present_from_id'] == player['id']:
            player_to = find_player_by_id(content, assignment['present_to_id'])
            break

    msg = MIMEText("Ciao " + player['name'] + ". Sono il babbo natale spegiale. \n" +
                   "A te è capitato da fare il regalo a: \n\n" +
                   player_to['name'] + "\n\n" +
                   "Buon divertimento!!!\n\n" +
                   "Codice estrazione: " + extr['extraction'])

    msg['Subject'] = "Spegial Secret Santa"
    msg['From'] = sender
    msg['To'] = player['email']

    with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp_server:
        smtp_server.login(sender, password)
        smtp_server.sendmail(sender, player['email'], msg.as_string())

        print("Email inviata con successo a ", player['email'])


def delete_extractions(content):
    content['extractions'] = []


def start():
    print("Hello SpeGial Secret Santa")
    print()

    content = load_data_from_file()

    choice_quit = False
    while not choice_quit:
        choice_quit = False
        print()
        print("Seleziona opzione:")
        print("1. Aggiungi giocatori")
        print("2. Salva")
        print("3. Visualizza giocatori")
        print("4. Aggiungi regola")
        print("5. Esegui estrazione")
        print("6. Avvisa giocatore")
        print("7. Avvisa tutti i giocatori")
        print("8. Cancella estrazioni")
        print("0. Esci")

        choice = int(input("Scelta:"))
        if choice == 1:
            add_user(content)
        elif choice == 2:
            save_data_to_file(content)
        elif choice == 3:
            show_players(content)
        elif choice == 4:
            add_rule(content)
        elif choice == 5:
            extraction(content)
        elif choice == 6:
            send_email(content)
        elif choice == 7:
            send_email_all(content)
        elif choice == 8:
            delete_extractions(content)
        elif choice == 0:
            print("Buon speGial secret santa")
            choice_quit = True
        else:
            print("Scelta non valida!!")


start()
