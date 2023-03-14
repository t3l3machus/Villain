



Desc = "Desc"
Det = "Details"
Min = "least_args"
Max = "max_args"
Act = "Action"
SPargs = "Special_args"


class pipe:
    def __init__(self):
        self.pipe = "|"
        self.forceprint = print
        self.pqueue : dict
        self.pqueue = {}
        self.pqueue_it = 0
        self.queue : list[str]
        self.queue = []
        self.call = 0
    def print(self, *values: object,sep: str | None = " ",end: str | None = "\n", **kwargs):
        val = str(values[0])
        values = values[1:]
        for v in values:
            val += sep + str(v) if not sep == None else str(v)
        self.pqueue[self.pqueue_it] = {}
        self.pqueue[self.pqueue_it]["val"] = val
        self.pqueue[self.pqueue_it]["end"] = end
        self.pqueue_it +=1
    def flush(self, out = True) -> list[str] | None:
        pqueue = []
        for i in range(0, self.pqueue_it):
            if out:
                print(self.pqueue[i]["val"], end=self.pqueue[i]["end"], flush=True)
            else:
                pqueue.append(self.pqueue[i]["val"])
        self.pqueue = {}
        if out:
            self.pqueue_it = 0
        else:  
            self.pqueue_it = 0
            return pqueue
    def unpipe_and_exec(self, cmds : list[str], commands_list, f, sessm, payloadm, core):
        pos = 0
        old_q = self.queue
        if self.pipe in cmds:
            for txt in cmds:
                if txt == self.pipe and pos < len(cmds):
                    self.queue = cmds[pos+1:]
                    break
                pos += 1
        if self.queue == old_q:
            self.queue = []
        cmd = cmds[0].lower() if cmds else ''
        if self.pipe in cmds:
            cmdlistlen = len(cmds[:pos])
            print(cmds)
            f(cmd, cmds[:pos], cmdlistlen, commands_list, sessm, payloadm, core)
        else:
            cmdlistlen = len(cmds)
            f(cmd, cmds, cmdlistlen, commands_list, sessm, payloadm, core)
        if len(self.queue) > 0:
            pqueue = self.flush(False)
            nxt = self.queue + pqueue
            self.unpipe_and_exec(nxt, commands_list, f, sessm, payloadm, core)
        elif len(self.queue) == 0:
            self.flush()
