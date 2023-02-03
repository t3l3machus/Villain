#!/usr/bin/env python3
"""Import and Manage all plugins in the \"Plugins\"-Folder"""
import os
import glob
import sys
import types
import re
from .common import FAIL, RED, ORANGE, END, INFO, FAILED, global_readline
class CMDStruct:
    "Structure for command objects"
    def __init__(self, name:str, Source:str, Plugin:str, cmd:dict[str, str | list[str] | int | None | types.FunctionType]):
        try:
            self.Name = name
            self.Source = Source
            self.Plugin = Plugin
            self.Details = cmd["Details"]
            self.Desc = cmd["Desc"]
            self.least_args = cmd["least_args"]
            self.max_args = cmd["max_args"]
            if callable(cmd["Action"]):
                self.Action = cmd["Action"]
            else:
                raise Action_not_Callable(name, Source)
            if self.max_args == 0:
                self.Args = False
            else:
                self.Args = True
            self.args = []
            if cmd["Special_args"] is None:
                self.spargs = False
            else:
                self.spargs = True
                for arg in cmd["Special_args"]:
                    self.args.append(arg.lower())
        except (TypeError ,KeyError):
            print(f"{FAILED} Invalid Command Structure in Plugin {Source}")

class Plugins:
    def __init__(self):
        print(f"[{INFO}] Loading Plugins...")
        self.main_help_msg = ""
        self.main_help_msg : str
        self.plugins : dict[str, types.ModuleType]
        self.plugins = {}
        self.pluginshelplist = {}
        self.commands : dict[str, CMDStruct]
        self.commands = {}
        self.specialargs = []
        self.specialargs : list[str]
        self.Plugin_being_processed = ""
        self.getplugins()
        self.getMainHelpMsg(self.commands)
        self.getPluginsHelpList(self.commands)
        self.getspargs()
    
    def getspargs(self):
        for cmd  in self.commands:
            spargs = self.commands[cmd].spargs
            if not spargs:
                continue
            else:
                self.specialargs.append(cmd)
    def findargs(self, s:list[str]) -> list[str]:
        input = s[-1].lower()
        possible_matches = self.commands[s[0]].args
        matches = [m.lower() for m in possible_matches if re.match(f"^{input}", m)]
        match = matches
        return match
    def getplugins(self):
        "Load every Plugin and their commands into a dict"
        pluginsfolder = os.path.join(os.getcwd(), "Plugins")
        for filename in glob.glob("*.py", root_dir=pluginsfolder):
            print(f"[{INFO}] Found Plugin {filename}")
            basename = filename.replace(".py", "")
            self.plugins[basename] = __import__("Plugins." + basename, None, None, (" "))
            PlObj = self.plugins[basename].Plugin()
            for name in PlObj.commands:
                if name in self.commands.keys():
                    raise cmd_duplicate(name, filename, self.commands[name].Source)
                cmd = PlObj.commands[name]
                self.commands[name] = CMDStruct(name, basename, PlObj.Name, cmd)
        
        PlObj = None
    def Execute(self, cmd, arg_list):
        "Execute a command"
        self.commands[cmd].Action(arg_list)
    def getMainHelpMsg(self, cmds : dict[str, CMDStruct]):
        "Constructing the main help Message for every command"
        for key in cmds:
            cmd = cmds[key]
            if not cmd.Source == self.Plugin_being_processed:
                print(f"[{INFO}] Adding Plugin {cmd.Source} to help...")
                self.Plugin_being_processed = cmd.Source
                self.main_help_msg += f"""
                \r  Plugin {cmd.Source}:\n"""
            cmd_lenght = len(cmd.Name)
            if cmd_lenght > 10:
                raise cmd_lenght_error(cmd.Name, cmd_lenght, cmd.Source)
            name = cmd.Name
            name += " " * (10 - cmd_lenght)
            self.main_help_msg += f"  {name}"
            if cmd.Args:
                self.main_help_msg += "[+]     "
            else:
                self.main_help_msg += "        "
            desc = cmd.Desc
            self.main_help_msg += f"{desc} \n"
    def getPluginsHelpList(self, cmds : dict[str, CMDStruct]):
        "Constructing the Detailed Help message for every command"
        for key in cmds:
            cmd = cmds[key]
            self.pluginshelplist[cmd.Name] = {
                "details" : cmd.Details,
                "least_args" : cmd.least_args,
                "max_args" : cmd.max_args
            }


class cmd_duplicate(BaseException):
    def __init__(self, name, source1, source2):
        message = f"[{FAILED}]{RED} The plugin {ORANGE}{source1}{FAIL} tried to declare the command {ORANGE}{name}{FAIL}, but it was already declared by the plugin {ORANGE}{source2}{FAIL}. {END}"
        print(message)
        sys.exit(-1)
class cmd_lenght_error(BaseException):
    def __init__(self, cmd : str, size : int, Source : str):
        message = f"[{FAILED}]{RED} The Command {ORANGE}{cmd}{FAIL} from the plugin {ORANGE}{Source}{FAIL} has a size of {ORANGE}{size}{FAIL} characters, but the maximum size is 10 characters. {END}"
        print(message)
        sys.exit(-1)
class Action_not_Callable(BaseException):
    def __init__(self, name:str, Source:str) -> None:
        message = f"[{FAILED}]{RED} The Command {ORANGE}{name}{FAIL} from the Plugin {ORANGE}{Source}{FAIL} failed to import because the command stored in the 'Action'-Field wasn't a callable"
        print(message)
        sys.exit(-1)