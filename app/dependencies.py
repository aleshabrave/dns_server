import json


def get_server_settings():
    with open("./settings.json", "r") as jsonfile:
        settings = json.load(jsonfile)
    return settings
