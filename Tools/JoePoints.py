#!/usr/bin/env python3
import sys
import requests
import json

PRIV_COMMANDS = {"genkey", "addperson", "removeperson", "setpoints", "addpoints", "removekey"}
NON_PRIV_COMMANDS = {"getuid", "getpoints", "getall", "getleaderboard", "help", "exit"}


def show_help(api_key):
    print("\nAvailable commands:")
    print("  help             - Show this help")
    if api_key:
        print("  genkey ID        - Generate new API key with identifier")
        print("  addperson F L    - Add new person with first and last name")
        print("  removeperson UID - Remove person by UID")
        print("  setpoints U P    - Set points for UID to value")
        print("  addpoints U P    - Add/subtract points for UID")
        print("  removekey       - Remove current API key")
    print("  getuid F L       - Get UIDs for first and last name")
    print("  getpoints UID    - Get points for UID")
    print("  getall          - List all users")
    print("  getleaderboard  - Show leaderboard")
    print("  exit            - Exit the program")
    print()

def pretty_print_response(endpoint, data):
    try:
        obj = json.loads(data)
    except json.JSONDecodeError:
        print(data)
        return

    if endpoint == "getall":
        if not obj:
            print("No users found.")
            return

        print(f"{'UID':<4} {'First':<10} {'Last':<10} {'Points':<6}")
        print("-" * 32)
        for user in obj:
            print(f"{user['uid']:<4} {user['first']:<10} {user['last']:<10} {user['points']:<6}")

    elif endpoint == "getleaderboard":
        if not obj:
            print("No users found.")
            return

        sorted_users = sorted(obj, key=lambda u: u['points'], reverse=True)
        print(f"{'Position':<8} {'Full Name':<25} {'Points':<6}")
        print("-" * 42)

        for i, user in enumerate(sorted_users, start=1):
            full_name = f"{user['first']} {user['last']}".strip()
            print(f"{i:<8} {full_name:<25} {user['points']:<6}")

    elif endpoint == "getuid":
        print("UIDs:", ", ".join(str(uid) for uid in obj))

    elif endpoint == "getpoints":
        print(f"Points: {obj['points']}")

    elif endpoint == "addperson":
        print(f"User added with UID: {obj['uid']}")

    elif endpoint == "genkey":
        print(f"New API key: {obj['key']}")

    elif endpoint in ["setpoints", "addpoints", "removeperson", "removekey"]:
        print(f"Status: {obj.get('status', 'ok')}")

    else:
        print(obj)


def run_command(cmd, server, headers, api_key):
    parts = cmd.strip().split()
    if not parts:
        return

    cmd_name = parts[0].lower()

    if not api_key and cmd_name in PRIV_COMMANDS:
        print("Error: This command requires an API key.")
        return

    try:
        if cmd_name == "help":
            show_help(api_key)

        elif cmd_name == "genkey":
            if len(parts) < 2:
                print("Usage: genkey IDENTIFIER")
                return
            identifier = parts[1]
            r = requests.post(f"{server}/api/genkey", headers=headers, json={"identifier": identifier})
            pretty_print_response("genkey", r.text)

        elif cmd_name == "addperson":
            first, last = parts[1], parts[2]
            r = requests.post(f"{server}/api/addperson", headers=headers, json={"first": first, "last": last})
            pretty_print_response("addperson", r.text)

        elif cmd_name == "removeperson":
            uid = int(parts[1])
            r = requests.post(f"{server}/api/removeperson", headers=headers, json={"uid": uid})
            pretty_print_response("removeperson", r.text)

        elif cmd_name == "getuid":
            first, last = parts[1], parts[2]
            r = requests.get(f"{server}/api/getuid", params={"first": first, "last": last})
            pretty_print_response("getuid", r.text)

        elif cmd_name == "getpoints":
            uid = int(parts[1])
            r = requests.get(f"{server}/api/getpoints", params={"uid": uid})
            pretty_print_response("getpoints", r.text)

        elif cmd_name == "setpoints":
            uid, points = int(parts[1]), int(parts[2])
            r = requests.post(f"{server}/api/setpoints", headers=headers, json={"uid": uid, "points": points})
            pretty_print_response("setpoints", r.text)

        elif cmd_name == "addpoints":
            uid, delta = int(parts[1]), int(parts[2])
            r = requests.post(f"{server}/api/addpoints", headers=headers, json={"uid": uid, "points": delta})
            pretty_print_response("addpoints", r.text)

        elif cmd_name == "getall":
            r = requests.get(f"{server}/api/getall")
            pretty_print_response("getall", r.text)

        elif cmd_name == "getleaderboard":
            r = requests.get(f"{server}/api/getall")
            pretty_print_response("getleaderboard", r.text)

        elif cmd_name == "removekey":
            r = requests.post(f"{server}/api/removekey", headers=headers)
            pretty_print_response("removekey", r.text)

        elif cmd_name == "exit":
            sys.exit(0)

        else:
            print("Unknown command. Type 'help' for commands.")

    except IndexError:
        print("Missing arguments for command.")

    except Exception as e:
        print(f"Error: {e}")


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} SERVER [API_KEY]")
        sys.exit(1)

    server = sys.argv[1]
    if not server.startswith("http://") and not server.startswith("https://"):
        server = "http://" + server

    api_key = sys.argv[2] if len(sys.argv) > 2 else None
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    print(f"Connected to {server}. Type 'help' for commands.")
    if not api_key:
        print("Running in non-privileged mode. Only non-privileged commands are available.")

    while True:
        try:
            cmd = input("> ")
            run_command(cmd, server, headers, api_key)
            
        except (KeyboardInterrupt, EOFError):
            print("\nExiting.")
            break


if __name__ == "__main__":
    main()
