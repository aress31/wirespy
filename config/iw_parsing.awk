BEGIN {
    regex_BSS = "^[[:alnum:]:]{17}$"
    regex_channel = "DS Parameter set: channel" # improve this regex
    printf("%-18.18s %-16.16s %8.8s %12.12s %12.12s %12.12s %6.6s %6.6s %6.6s %6.6s %6.6s\n", "BSSID", "SSID", "Channel", "Frequency", "Signal (dBm)", "Signal (%)", "WPS", "WPA", "WPA2", "WEP", "TKIP", "CCMP")
}

NF > 0 {
    if ($1 == "BSS") {
        if (match($2, regex_BSS)) {
            BSSID = $2
            dict[BSSID]["WPS"]  = "NO"
            dict[BSSID]["WPA"]  = "NO"
            dict[BSSID]["WPA2"] = "NO"
            dict[BSSID]["WEP"]  = "NO"
            dict[BSSID]["TKIP"] = "NO"
            dict[BSSID]["CCMP"] = "NO"
        }
    }

    if ($1 == "SSID:") {
        dict[BSSID]["SSID"] = $NF
    }

    if (match($0, regex_channel)) {
        dict[BSSID]["channel"] = $NF
    }

    if ($1 == "freq:") {
        dict[BSSID]["freq"] = $NF
    }

    if ($1 == "signal:") {
        dict[BSSID]["signal"]  = $2
        dict[BSSID]["signal%"] = (60 - ((-$2) - 40)) * 100 / 60
    }

    if ($1 == "WPS:") {
        dict[BSSID]["WPS"] = "YES"
    }

    if ($1 == "WPA:") {
        dict[BSSID]["WPA"] = "YES"
    }

    if ($1 == "RSN:") {
        dict[BSSID]["WPA2"] = "YES"
    }

    if ($1 == "WEP:") {
        dict[BSSID]["WEP"] = "YES"
    }

    if ($NF == "CCMP") {
        dict[BSSID]["CCMP"] = "YES"
    }

    if ($NF == "TKIP") {
        dict[BSSID]["TKIP"] = "YES"
    }
}

END {
    for (BSSID in dict) {
        printf("%-18.18s %-16.16s %8.8s %12.12s %12.12s %12.12s %6.6s %6.6s %6.6s %6.6s %6.6s\n", BSSID, dict[BSSID]["SSID"], dict[BSSID]["channel"], dict[BSSID]["freq"], dict[BSSID]["signal"], dict[BSSID]["signal%"], dict[BSSID]["WPS"], dict[BSSID]["WPA"], dict[BSSID]["WPA2"], dict[BSSID]["WEP"], dict[BSSID]["TKIP"], dict[BSSID]["CCMP"])
    }
}
