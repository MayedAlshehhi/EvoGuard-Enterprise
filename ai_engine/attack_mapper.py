def map_attack_category(attack_label):
    attack_label = attack_label.lower()

    dos_attacks = [
        "back", "land", "neptune", "pod", "smurf", "teardrop",
        "apache2", "udpstorm", "processtable", "worm"
    ]

    probe_attacks = [
        "satan", "ipsweep", "nmap", "portsweep", "mscan", "saint"
    ]

    r2l_attacks = [
        "guess_passwd", "ftp_write", "imap", "phf", "multihop",
        "warezmaster", "warezclient", "spy", "xlock", "xsnoop",
        "snmpguess", "snmpgetattack", "httptunnel", "sendmail",
        "named"
    ]

    u2r_attacks = [
        "buffer_overflow", "loadmodule", "rootkit", "perl",
        "sqlattack", "xterm", "ps"
    ]

    if attack_label == "normal":
        return "Normal"

    if attack_label in dos_attacks:
        return "DoS / DDoS"

    if attack_label in probe_attacks:
        return "Probe / Scanning"

    if attack_label in r2l_attacks:
        return "R2L / Unauthorized Access"

    if attack_label in u2r_attacks:
        return "U2R / Privilege Escalation"

    return "Unknown Attack"