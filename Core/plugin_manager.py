#!/usr/bin/env python3
"""Import and Manage all plugins in the \"Plugins\"-Folder"""
import os
import glob
import sys
from .common import FAIL, RED, ORANGE, END, INFO, FAILED

class Plugins:
    def __init__(self):
        print(f"[{INFO}] Loading Plugins...")
        self.main_help_msg = """\r"""
        self.plugins = {}
        self.pluginshelplist = {}
        self.commands = {}
        self.Plugin_being_processed = ""
        self.processed_plugins = []
        self.getplugins()

    def getplugins(self):
        pluginsfolder = os.path.join(os.getcwd(), "Plugins")
        print(os.getcwd())
        print(pluginsfolder)
        for filename in glob.glob("*.py", root_dir=pluginsfolder):
            print(f"[{INFO}] Found Plugin {filename}")
            basename = filename.replace(".py", "")
            self.plugins[basename] = __import__("Plugins." + basename, None, None, (" "))
            PlObj = self.plugins[basename].Plugin()
            for name in PlObj.commands:
                if name in self.commands.keys():
                    raise cmd_duplicate(name, filename, self.commands[name]["Source"])
                cmd = PlObj.commands[name]
                self.commands[name] = {
                    "Source" : basename,
                    "Plugin" : PlObj.Name,
                    "Details" : cmd["Details"],
                    "Desc" : cmd["Desc"],
                    "least_args" : cmd["least_args"],
                    "max_args" : cmd["max_args"],
                    "Action" : cmd["Action"],
                    "Args" : bool(False if cmd["max_args"] == 0 else True)
                }
                print(self.commands[name]["Source"])
                self.getMainHelpMsg(name, self.commands[name], PlObj.Name)
                self.getPluginsHelpList(name, self.commands[name])
        
        PlObj = None
    def Execute(self, cmd, arg_list):
        func = self.commands[cmd]["Action"]
        fname = self.commands[cmd]["Source"]
        print(fname)
        exec(f"self.plugins[\"{fname}\"].{func}({arg_list})")
    def getMainHelpMsg(self, cmd : str, info : dict[str, str | int | bool], Source : str):
        if not Source == self.Plugin_being_processed:
            print(f"[{INFO}] Adding Plugin {Source} to help...")
            self.Plugin_being_processed = Source
            self.main_help_msg += f"""
            \r  Plugin {Source}:\n"""
        cmd_lenght = len(cmd)
        if cmd_lenght > 10:
            raise cmd_lenght_error(cmd, cmd_lenght, Source)
        name = cmd
        name += " " * (10 - cmd_lenght)
        self.main_help_msg += f"  {name}"
        if info["Args"]:
            self.main_help_msg += "[+]     "
        else:
            self.main_help_msg += "        "
        desc = info["Desc"]
        self.main_help_msg += f"{desc} \n"
    def getPluginsHelpList(self, cmd :str, info : dict[str, str|int|bool]):
        self.pluginshelplist[cmd] = {
            "details" : info["Details"],
            "least_args" : info["least_args"],
            "max_args" : info["max_args"]
        }



class cmd_duplicate(Exception):
    def __init__(self, name, source1, source2):
        message = f"[{FAILED}]{RED} The plugin {ORANGE}{source1}{FAIL} tried to declare the command {ORANGE}{name}{FAIL}, but it was already declared by the plugin {ORANGE}{source2}{FAIL}. {END}"
        print(message)
        sys.exit(1)
class cmd_lenght_error(Exception):
    def __init__(self, cmd : str, size : int, Source : str):
        message = f"[{FAILED}]{RED} The Command {ORANGE}{cmd}{FAIL} from the plugin {ORANGE}{Source}{FAIL} has a size of {ORANGE}{size}{FAIL} characters, but the maximum size is 10 characters. {END}"
        print(message)
        sys.exit(1)