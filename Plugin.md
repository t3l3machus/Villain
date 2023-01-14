class Plugin:
    Name = "Plugin Name"
    commands = {
        CommandName : {
            "Desc" : "Quick Description that fits into one single line" -> str,
            "Details" : "Multi-Line Detailed Explanation of the command, Its arguments and its use" -> str,
            "least_args" : Minimum of Args required for this Command -> int,
            "max_args" : Maximum of Args accepted by this Command -> int,
            "Action" : "Name of a Function Somewhere outside of this class inside of this file (without these : '()' " -> str
        }
    }help