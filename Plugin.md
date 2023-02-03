```
class Plugin:
    Name = "Plugin Name"
    commands = {
        CommandName : {
            "Desc" : "Quick Description that fits into one single line" -> str,
            "Details" : "Multi-Line Detailed Explanation of the command, Its arguments and its use" -> str,
            "least_args" : Minimum of Args required for this Command -> int,
            "max_args" : Maximum of Args accepted by this Command -> int,
            "Action" : a function (without '()') placed somewhwere outside of this class before the definition of this class, -> callable
            "Special_args" : [listofargs] or None -> list[str] | None
            }
        }
    }


```