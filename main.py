# coding=utf-8
import datetime
from os.path import exists
import json
import random
import smtplib
from email.mime.text import MIMEText
from cryptography.fernet import Fernet
from getpass import getpass
import hashlib

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
        disabled_str = "" if 'disabled' not in player or not player['disabled'] else "(disabilitato)"

        print(player['id'], player['name'], player['email'], disabled_str)

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

    players = [p for p in content['players'] if 'disabled' not in p or not p['disabled']]

    ok = False
    players_shuffled = random.sample(players, len(players))
    rules = get_extraction_rules(content)

    # this algo is a brute force over players and will be *very* inefficient as years go by
    # todo: replace it with a CSP-style algorithm

    attempts = 0
    while not ok:
        ok = True
        players_shuffled = random.sample(players, len(players))
        attempts += 1

        for i in range(0, len(players_shuffled)):
            present_from_id = players[i]['id']
            present_to_id = players_shuffled[i]['id']

            for rule in rules:
                if rule['player_from'] == present_from_id and rule['player_to'] == present_to_id:
                    ok = False

    result = []
    for i in range(0, len(players_shuffled)):
        present_from_id = players[i]['id']
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

    name = input("Dai un nome all'estrazione:")
    test = input("Scrivi T se questa estrazione è di test:")
    is_test = test == "T"

    content['extractions'].append({
        'id': extraction_id,
        'name': name,
        'extraction': encoded_extraction.decode('utf-8'),
        'test': is_test
    })

    if is_test:
        print("Rivelazione estrazione TEST")
        reveal(content, result)

    hash = hashlib.md5(encoded_extraction)

    print("Estrazione ok con tentativi:", attempts, ", id", extraction_id, ",hash", hash.hexdigest())


def get_extraction_rules(content):
    key = content['key'].encode('utf-8')
    fernet = Fernet(key)

    rules = []

    for player in content['players']:
        rules.append({
            'player_from': player['id'],
            'player_to': player['id']
        })

    for rule in content['rules']:
        rules.append(rule)

    for extr in content['extractions']:
        if 'test' in extr and extr['test']:
            continue

        decrypted_extraction = json.loads(fernet.decrypt(extr['extraction']).decode())

        for assignment in decrypted_extraction:
            rule_existing = False
            for existing_rule in rules:
                if existing_rule['player_from'] == assignment['present_from_id'] and existing_rule['player_to'] == assignment['present_to_id']:
                    rule_existing = True
                    break

            if not rule_existing:
                rules.append({
                    'player_from': assignment['present_from_id'],
                    'player_to': assignment['present_to_id']
                })

    return rules


def reveal(content, extraction):
    for assignment in extraction:
        player_from = find_player_by_id(content, assignment['present_from_id'])
        player_to = find_player_by_id(content, assignment['present_to_id'])

        print(player_from['name'], "->", player_to['name'])


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

    print('Trovata estrazione con id', extraction_id, 'e nome', extr['name'])

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

    print('Trovata estrazione con id', extraction_id, 'e nome', extr['name'])

    sender = input("Indirizzo email di invio: ")
    password = getpass("Inserisci password email per l'invio: ")

    for player in content['players']:
        send_email_to_player(content, player, extr, sender, password)


def send_email_to_player(content, player, extr, sender, password):
    key = content['key'].encode('utf-8')
    fernet = Fernet(key)
    extraction_hash = hashlib.md5(extr['extraction'].encode('utf-8')).hexdigest()

    decrypted_extraction = json.loads(fernet.decrypt(extr['extraction']).decode())

    player_to = None

    for assignment in decrypted_extraction:
        if assignment['present_from_id'] == player['id']:
            player_to = find_player_by_id(content, assignment['present_to_id'])
            break

    year = str(datetime.datetime.now().year)
    is_test = "TEST" if 'test' in decrypted_extraction and decrypted_extraction['test'] else "UFFICIALE"

    msg = MIMEText("Ciao " + player['name'] + ". Sono di nuovo il babbo natale spegiale. \n" +
                   "Questa è la mail di estrazione per l'anno "+year+" \""+extr['name']+"\". Alcune regole: \n\n"
                   "1. Non dire a nessuno chi ti è appena capitato\n" +
                   "2. Non regalare un iPod\n" +
                   "3. Non rispondere a questa mail\n" +
                   "4. Sii originale e divertiti!!\n\n" +
                   "E ora il risultato dell'estrazione...\n\n"
                   "Devi fare il regalo a: \n\n" +
                   player_to['name'] + "\n\n" +
                   "Buon divertimento!!!\n\n" +
                   "Codice estrazione: " + extraction_hash)

    msg['Subject'] = "Spegial Secret Santa "+is_test+" "+year
    msg['From'] = sender
    msg['To'] = player['email']

    with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp_server:
        smtp_server.login(sender, password)
        smtp_server.sendmail(sender, player['email'], msg.as_string())

        print("Email inviata con successo a ", player['email'])


def delete_extractions(content):
    content['extractions'] = []


def toggle_enabled_player(content):
    choice = int(input("Inserisci numero giocatore: "))

    player = find_player_by_id(content, choice)
    if player is None:
        print("Non ho trovato il giocatore con id", choice)
        return

    disabled = False
    if 'disabled' not in player or player['disabled'] == False:
        print("Giocatore", player['name'], "è abilitato")
    else:
        print("Giocatore", player['name'], "non è abilitato")
        disabled = True

    choice = input("Cambiare abilitazione? (S/N)")

    if choice == "S":
        new_state = not disabled
        player['disabled'] = new_state
        if new_state:
            print("Giocatore", player['name'], "non è più abilitato")
        else:
            print("Giocatore", player['name'], "ora è abilitato")


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
        print("9. Disabilita/abilita giocatore")
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
        elif choice == 9:
            toggle_enabled_player(content)
        elif choice == 0:
            print("Buon speGial secret santa")
            choice_quit = True
        else:
            print("Scelta non valida!!")


start()
