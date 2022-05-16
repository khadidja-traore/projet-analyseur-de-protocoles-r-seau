import string
import tkinter
import tkinter.ttk

fichier = input("Quel fichier dois-je considérer ? ")
try:
    file = open(fichier, "r")
except:
    print("Le fichier est introuvable, veuillez réessayer")

ligne = file.read()

l = ligne.split()

carAccepeted = list(string.ascii_lowercase) + list(string.ascii_uppercase) + list(string.digits)
S = []

f_res = open("resultat.txt", "w")  # fichier avec les résultats

fenetre = tkinter.Tk()
fenetre.title("Analyseur")

arbre = tkinter.ttk.Treeview(fenetre)

arbre.column("#0", width=600, minwidth=100, stretch=False)
arbre.heading("#0", text="Trames", anchor="w")


def trames():
    global S
    i = 0
    ligne = 1
    id_erreur = 1000

    while l[i] != "0000":
        if len(l[i]) == 4:
            ligne = ligne + 1
        i = i + 1

    tab = []
    while i < len(l):
        if l[i] == "0000":
            if tab != []:
                S.append(tab)

            longeur = 0
            tab = []
            i = i + 1
        else:
            t = []
            while i < len(l):
                if len(l[i]) == 2:
                    t.append(l[i])
                    i = i + 1
                else:
                    break
            i = i + 1
            if len(t) != 16:
                if i < len(l):

                    if l[i] != "0000":

                        a = "La ligne " + str(ligne) + "est incomplète !\n"
                        f_res.write(a)
                        arbre.insert("", 'end', id_erreur, text="La ligne " + str(ligne) + " est incomplète !",
                                     open=False)
                        id_erreur += 1

                        tab = []
                        while i < len(l):
                            if len(l[i]) == 4:
                                ligne = ligne + 1
                            if l[i] == "0000":
                                ligne = ligne + 1
                                break
                            else:
                                i = i + 1
                    else:
                        ligne = ligne + 1
                        tab = tab + t
                else:
                    tab = tab + t
            else:
                longeur = longeur + 16
                tab = tab + t
                while i < len(l):
                    if l[i] == "0000":
                        ligne = ligne + 1
                        break
                    else:
                        if len(l[i]) == 4:
                            ligne = ligne + 1
                            if int(l[i], 16) == longeur:
                                # car on doit rentrer dans else(if l[i]="0000") avec la position du caractere apres l'offset valide
                                i = i + 1
                                break
                            else:
                                i = i + 1
                        else:
                            i = i + 1

    S.append(tab)


def retirerchamp(liste, tailleChamp):
    global i

    if tailleChamp > 0:
        champ = ""
        n = i
        for i in range(n, n + tailleChamp):
            if i >= len(liste):
                return ("vide")
            champ = champ + liste[i]
        i = i + 1
        if champ == "":
            return ("vide")
        return (champ)
    else:
        return "vide"


def retirerChampHTTP(l, jusquaOctet):
    global i
    champ = ""

    if i >= len(l):
        return "vide"

    if len(jusquaOctet) == 2:
        while i + 1 < len(l):
            octet = l[i] + l[i + 1]
            if octet != jusquaOctet.upper() and octet != jusquaOctet.lower():
                champ = champ + chr(int(octet, 16))
                i = i + 2
            else:
                i = i + 2
                break
        return champ

    else:

        while i + 3 < len(l):
            octet1 = l[i] + l[i + 1]
            octet2 = l[i + 2] + l[i + 3]
            octet = octet1 + octet2
            if octet != jusquaOctet.upper() and octet != jusquaOctet.lower():
                champ = champ + chr(int(octet1, 16))
                i = i + 2
            else:
                i = i + 4
                break
        return champ


def analyseur():
    var_id = 1

    global i
    for numtrame in range(len(S)):

        var_idtrame = numtrame + 1
        var_idpro = 1
        var_idchamp = 1

        a = "Trame " + str(var_idtrame) + "\n"
        f_res.write(a)

        text_trame = "Trame", var_idtrame
        id_trame = "T", var_idtrame
        arbre.insert("", 'end', id_trame, text=text_trame, open=True)

        i = 0
        trame = S[numtrame]
        liste = []

        for j in range(len(trame)):
            liste = liste + list(trame[j])

        adr_Mac_dest = retirerchamp(liste, 12)
        adr_Mac_src = retirerchamp(liste, 12)
        typeEthernet = retirerchamp(liste, 4)

        # ecriture dans le fichier resulat.txt
        f_res.write("   Entête Ethernet\n")
        a = "       Adresse Mac destination: " + str(adr_Mac_dest) + "\n"
        f_res.write(a)
        a = "       Adresse Mac source: " + str(adr_Mac_src) + "\n"
        f_res.write(a)

        # noeud entete ethernet
        numpro = "", id_trame, "pr", var_idpro
        var_idpro += 1
        arbre.insert(id_trame, 'end', numpro, text="Entête Ethernet", open=True)

        # noeud des champs
        numchamp = "", numpro, "champ", var_idchamp
        arbre.insert(numpro, 'end', numchamp, text="Adresse Mac destination: " + str(adr_Mac_dest), open=False)
        var_idchamp += 1

        numchamp = "", numpro, "champ", var_idchamp
        arbre.insert(numpro, 'end', numchamp, text="Adresse Mac source: " + str(adr_Mac_src), open=False)
        var_idchamp += 1

        if typeEthernet == "0800":
            typeEthernetSignification = " (datagramme IP)"

            a = "       Type: " + str(typeEthernet) + str(typeEthernetSignification) + "\n"
            f_res.write(a)

            numchamp = "", numpro, "champ", var_idchamp
            arbre.insert(numpro, 'end', numchamp, text="Type: " + str(typeEthernet) + str(typeEthernetSignification),
                         open=False)
            var_idchamp += 1

            versionIP = retirerchamp(liste, 1)

           
            if versionIP == '4':
                versionIpSignification = " (Ipv4)"

            ihlIP = retirerchamp(liste, 1)
            ihlIPDec = int(ihlIP, 16) * 4
            lenghIPOptionDec = ihlIPDec - 20

           

            TOS = retirerchamp(liste, 2)

            totallenghIP = retirerchamp(liste, 4)
            totallenghIPDec = int(totallenghIP, 16)
            lenghIPDataDec = totallenghIPDec - ihlIPDec

            identifierIP = retirerchamp(liste, 4)

            fragmentComplet = retirerchamp(liste, 4)
            fragmentBin = bin(int(fragmentComplet, 16))
            # le format de bin est Ob... donc on enleve les 2 premiers caracteres
            fragmentBin = fragmentBin[2:]
            n = len(fragmentBin)
            for o in range(n, 16):
                fragmentBin = "0" + fragmentBin
            flagFragment = str(fragmentBin[0])
            DF = str(fragmentBin[1])
            MF = str(fragmentBin[2])
            fragmentOffset = str(fragmentBin[3:])

            TTLIP = retirerchamp(liste, 2)
            significationTTLIP = " (" + str(int(TTLIP, 16)) + ")"

            protocol = retirerchamp(liste, 2)
            protocolSignification = ""
            if protocol == "01":
                protocolSignification = "(ICMP)"
            elif protocol == "02":
                protocolSignification = "(IGMP)"
            elif protocol == "06":
                protocolSignification = "(TCP)"
            elif protocol == "08":
                protocolSignification = "(EGP)"
            elif protocol == "09":
                protocolSignification = "(IGP)"
            elif protocol == "11":
                protocolSignification = "(UDP)"

            headerChecksumIP = retirerchamp(liste, 4)

            adresseIpSrc = retirerchamp(liste, 8)
            adressIpSrcDecimal = ""
            j = 1
            while j < len(adresseIpSrc):
                octet = adresseIpSrc[j - 1] + adresseIpSrc[j]
                adressIpSrcDecimal = adressIpSrcDecimal + str(int(octet, 16)) + "."
                j += 2

            adresseIpDest = retirerchamp(liste, 8)
            adressIpDestDecimal = ""
            j = 1
            while j < len(adresseIpSrc):
                octet = adresseIpDest[j - 1] + adresseIpDest[j]
                adressIpDestDecimal = adressIpDestDecimal + str(int(octet, 16)) + "."
                j += 2

            l = i
            # on verifie a chaque fin d'une option si on est arrivé a la taille calculé precedemment grace a la taille de l'entete
            option = []
            while (i < l + lenghIPOptionDec * 2):
                typeOption = retirerchamp(liste, 2)
                if typeOption == "00":
                    typeOptionSignification = " (end of option list)"
                    option.append(["type: " + typeOption + typeOptionSignification])
                    continue
                if typeOption == "01":
                    typeOptionSignification = " (NO operation ,NOP)"
                if typeOption == "07":
                    typeOptionSignification = " (Record Route ,RR)"
                if typeOption == "44":
                    typeOptionSignification = " (Time Stamp)"
                if typeOption == "83":
                    typeOptionSignification = " (Loose Source Route ,LRS)"
                if typeOption == "89":
                    typeOptionSignification = " (Strict Source Route ,SSR)"

                longeurOpt = retirerchamp(liste, 2)
                if longeurOpt == "vide":
                    longeurOptDec = 0
                else:
                    longeurOptDec = int(longeurOpt, 16)
                pointeur = retirerchamp(liste, 2)
                # la longeur est en octet et 1octet= 2symboles donc
                option.append(["type: " + typeOption + typeOptionSignification, "pointeur: " + pointeur,
                               "valeur:" + retirerchamp(liste, longeurOptDec * 2 - 6)])

            a = "   Entête IP\n"
            f_res.write(a)
            numpro = "", id_trame, "pr", var_idpro
            var_idpro += 1
            arbre.insert(id_trame, 'end', numpro, text="Entête IP", open=True)

            a = "       Version: " + str(versionIP) + " " + str(versionIpSignification) + "\n"
            f_res.write(a)

            numchamp = "", numpro, "champ", var_idchamp
            arbre.insert(numpro, 'end', numchamp, text="Version: " + str(versionIP) + " " + str(versionIpSignification),
                         open=False)
            var_idchamp += 1

            a = "       IHL: " + str(ihlIP) + " (" + str(ihlIPDec) + " octets)\n"
            f_res.write(a)
            numchamp = "", numpro, "champ", var_idchamp
            arbre.insert(numpro, 'end', numchamp, text="IHL: " + str(ihlIP) + " (" + str(ihlIPDec) + " octets)",
                         open=False)
            var_idchamp += 1

            a = "       TOS: " + str(TOS) + "\n"
            f_res.write(a)
            numchamp = "", numpro, "champ", var_idchamp
            arbre.insert(numpro, 'end', numchamp, text="TOS: " + str(TOS), open=False)
            var_idchamp += 1

            a = "       Longueur totale: " + str(totallenghIP) + " (" + str(totallenghIPDec) + " octets)\n"
            f_res.write(a)
            numchamp = "", numpro, "champ", var_idchamp
            arbre.insert(numpro, 'end', numchamp,
                         text="Longueur totale: " + str(totallenghIP) + " (" + str(totallenghIPDec) + " octets)",
                         open=False)
            var_idchamp += 1

            a = "       Identification: " + str(identifierIP) + "\n"
            f_res.write(a)
            numchamp = "", numpro, "champ", var_idchamp
            arbre.insert(numpro, 'end', numchamp, text="Identification: " + str(identifierIP), open=False)
            var_idchamp += 1

            a = "       Drapeaux + Fragment Offset: " + str(fragmentComplet) + ", FlagFragment= " + str(
                flagFragment) + ", DF = " + str(DF) + ", MF = " + str(MF) + "\n"
            f_res.write(a)
            numchamp = "", numpro, "champ", var_idchamp
            arbre.insert(numpro, 'end', numchamp,
                         text="Drapeaux + Fragment Offset: " + str(fragmentComplet) + ", FlagFragment= " + str(
                             flagFragment) + ", DF = " + str(DF) + ", MF = " + str(MF), open=False)
            var_idchamp += 1

            a = "       TTL: " + str(TTLIP) + significationTTLIP + "\n"
            f_res.write(a)
            numchamp = "", numpro, "champ", var_idchamp
            arbre.insert(numpro, 'end', numchamp, text="TTL: " + str(TTLIP)+ significationTTLIP, open=False)
            var_idchamp += 1

            a = "       Protocole: " + str(protocol) + " " + str(protocolSignification) + "\n"
            f_res.write(a)
            numchamp = "", numpro, "champ", var_idchamp
            arbre.insert(numpro, 'end', numchamp, text="Protocole: " + str(protocol) + " " + str(protocolSignification),
                         open=False)
            var_idchamp += 1

            a = "       Somme de contrôle de l'entête: " + str(headerChecksumIP) + "\n"
            f_res.write(a)
            numchamp = "", numpro, "champ", var_idchamp
            arbre.insert(numpro, 'end', numchamp, text="Somme de contrôle de l'entête: " + str(headerChecksumIP),
                         open=False)
            var_idchamp += 1

            a = "       Adresse IP source: " + str(adresseIpSrc) + " (" + str(adressIpSrcDecimal) + ") \n"
            f_res.write(a)
            numchamp = "", numpro, "champ", var_idchamp
            arbre.insert(numpro, 'end', numchamp,
                         text="Adresse IP source: " + str(adresseIpSrc) + " (" + str(adressIpSrcDecimal) + ")",
                         open=False)
            var_idchamp += 1

            a = "       Adresse IP destination: " + str(adresseIpDest) + " (" + str(adressIpDestDecimal) + ")\n"
            f_res.write(a)
            numchamp = "", numpro, "champ", var_idchamp
            arbre.insert(numpro, 'end', numchamp,
                         text="Adresse IP destination: " + str(adresseIpDest) + " (" + str(adressIpDestDecimal) + ")",
                         open=False)
            var_idchamp += 1

            a = "       Options: " + str(option) + "\n"
            f_res.write(a)
            numchamp = "", numpro, "champ", var_idchamp
            arbre.insert(numpro, 'end', numchamp, text="Options: " + str(option), open=False)
            var_idchamp += 1

            # protocole TCP
            if protocol == "06":
                sourceport = retirerchamp(liste, 4)
                significationSourceport = " (" + str(int(sourceport, 16)) + ")"

                destinationport = retirerchamp(liste, 4)
                significationDestinationport = " (" + str(int(destinationport, 16)) + ")"

                sequenceNumber = retirerchamp(liste, 8)
                significationSequenceNumber = " (" + str(int(sequenceNumber, 16)) + ")"

                acknowledgementNumber = retirerchamp(liste, 8)
                significationAcknowledgmentNumber = " (" + str(int(acknowledgementNumber, 16)) + ")"

                # taille de l'entete TCP
                thlTcp = retirerchamp(liste, 1)
                thlTcpDec = int(thlTcp, 16) * 4

                flags = retirerchamp(liste, 3)
                flagsBin = bin(int(flags, 16))
                flagsBin = flagsBin[2:]
                n = len(flagsBin)
                for o in range(n, 12):
                    flagsBin = "0" + flagsBin
                urg = flagsBin[6]
                ack = flagsBin[7]
                psh = flagsBin[8]
                rst = flagsBin[9]
                syn = flagsBin[10]
                fin = flagsBin[11]

                window = retirerchamp(liste, 4)
                significationWindow = " (" + str(int(window, 16)) + ")"

                checksumTcp = retirerchamp(liste, 4)

                urgentpointer = retirerchamp(liste, 4)

                lenghtOptTcpDec = thlTcpDec - 20

                l = i
                # on verifie a chaque fin d'une option si on est arrivé a la taille calculé precedemment grace a la taille de l'entete
                optionTCP = []
                while (i < l + lenghtOptTcpDec * 2):
                    typeOption = retirerchamp(liste, 2)
                    if typeOption == "00":
                        typeOptionSignification = " (end of option list)"
                        optionTCP.append(["type: " + typeOption + typeOptionSignification])
                        continue
                    if typeOption == "01":
                        typeOptionSignification = " (NO operation ,NOP)"
                        optionTCP.append(["type: " + typeOption + typeOptionSignification])
                        continue
                    if typeOption == "02":
                        typeOptionSignification = " (Maximum segment size ,MSS)"
                    if typeOption == "03":
                        typeOptionSignification = " (WSOPT -window soale)"
                    if typeOption == "04":
                        typeOptionSignification = " (SACK permitted)"
                    if typeOption == "05":
                        typeOptionSignification = " (SACK(selective ACK))"
                    if typeOption == "06":
                        typeOptionSignification = " (ECHO)"
                    if typeOption == "07":
                        typeOptionSignification = " (ECHO Reply)"
                    if typeOption == "08":
                        typeOptionSignification = " (TSOPT-time stamp option)"
                    if typeOption == "09":
                        typeOptionSignification = " (partiel order connection permitted)"
                    if typeOption == "0A" or typeOption == "0a":
                        typeOptionSignification = " (partiel order service profile)"
                    if typeOption == "0B" or typeOption == "0b":
                        typeOptionSignification = " (CC)"
                        optionTCP.append(["type: " + typeOption + typeOptionSignification])
                        continue
                    if typeOption == "0C" or typeOption == "0c":
                        typeOptionSignification = " (CC.NEW)"
                        optionTCP.append(["type: " + typeOption + typeOptionSignification])
                        continue
                    if typeOption == "0D" or typeOption == "0d":
                        typeOptionSignification = " (CC.ECHO)"
                        optionTCP.append(["type: " + typeOption + typeOptionSignification])
                        continue
                    if typeOption == "0E" or typeOption == "0e":
                        typeOptionSignification = " (TCP.Alternate checksum request)"
                    if typeOption == "0F" or typeOption == "0f":
                        typeOptionSignification = " (TCP Alternate checksum data)"

                    longeurOpt = retirerchamp(liste, 2)
                    longeurOptDec = int(longeurOpt, 16)

                    # la longeur est en octet et 1octet= 2symboles donc
                    optionTCP.append(
                        ["Type: " + typeOption + typeOptionSignification, "Longueur: " + str(longeurOptDec),
                         "Valeur: " + retirerchamp(liste, longeurOptDec * 2 - 4)])

                # lenghTcpData = lenghIPDataDec - thlTcpDec
                # dataTCP = retirerchamp(liste, lenghTcpData * 2)

                a = "   Entête TCP\n"
                f_res.write(a)
                numpro = "", id_trame, "pr", var_idpro
                var_idpro += 1
                arbre.insert(id_trame, 'end', numpro, text="Entête TCP", open=True)

                a = "       Port source: " + str(sourceport) + significationSourceport + "\n"
                f_res.write(a)
                numchamp = "", numpro, "champ", var_idchamp
                arbre.insert(numpro, 'end', numchamp, text="Port source: " + str(sourceport)+ significationSourceport, open=False)
                var_idchamp += 1

                a = "       Port destination: " + str(destinationport) + significationDestinationport + "\n"
                f_res.write(a)
                numchamp = "", numpro, "champ", var_idchamp
                arbre.insert(numpro, 'end', numchamp, text="Port destination: " + str(destinationport) + significationSourceport, open=False)
                var_idchamp += 1

                a = "       Numéro de séquence: " + str(sequenceNumber) +significationSequenceNumber + "\n"
                f_res.write(a)
                numchamp = "", numpro, "champ", var_idchamp
                arbre.insert(numpro, 'end', numchamp, text="Numéro de séquence: " + str(sequenceNumber) + significationSequenceNumber, open=False)
                var_idchamp += 1

                a = "       Numéro d'acquittement: " + str(acknowledgementNumber)+ significationAcknowledgmentNumber + "\n"
                f_res.write(a)
                numchamp = "", numpro, "champ", var_idchamp
                arbre.insert(numpro, 'end', numchamp, text="Numéro d'acquittement: " + str(acknowledgementNumber) + significationAcknowledgmentNumber,
                             open=False)
                var_idchamp += 1

                a = "       THL TCP: " + str(thlTcp) + " (" + str(thlTcpDec) + " octets)\n"
                f_res.write(a)
                numchamp = "", numpro, "champ", var_idchamp
                arbre.insert(numpro, 'end', numchamp,
                             text="THL TCP: " + str(thlTcp) + " (" + str(thlTcpDec) + " octets)", open=False)
                var_idchamp += 1

                a = "       URG = " + str(urg) + "\n"
                f_res.write(a)
                numchamp = "", numpro, "champ", var_idchamp
                arbre.insert(numpro, 'end', numchamp, text="URG = " + str(urg), open=False)
                var_idchamp += 1

                a = "       ACK = " + str(ack) + "\n"
                f_res.write(a)
                numchamp = "", numpro, "champ", var_idchamp
                arbre.insert(numpro, 'end', numchamp, text="ACK = " + str(ack), open=False)
                var_idchamp += 1

                a = "       PSH = " + str(psh) + "\n"
                f_res.write(a)
                numchamp = "", numpro, "champ", var_idchamp
                arbre.insert(numpro, 'end', numchamp, text="PSH = " + str(psh), open=False)
                var_idchamp += 1

                a = "       RST = " + str(rst) + "\n"
                f_res.write(a)
                numchamp = "", numpro, "champ", var_idchamp
                arbre.insert(numpro, 'end', numchamp, text="RST = " + str(rst), open=False)
                var_idchamp += 1

                a = "       SYN = " + str(syn) + "\n"
                f_res.write(a)
                numchamp = "", numpro, "champ", var_idchamp
                arbre.insert(numpro, 'end', numchamp, text="SYN = " + str(syn), open=False)
                var_idchamp += 1

                a = "       FIN = " + str(fin) + "\n"
                f_res.write(a)
                numchamp = "", numpro, "champ", var_idchamp
                arbre.insert(numpro, 'end', numchamp, text="FIN = " + str(fin), open=False)
                var_idchamp += 1

                a = "       Fenêtre = " + str(window) +significationWindow + "\n"
                f_res.write(a)
                numchamp = "", numpro, "champ", var_idchamp
                arbre.insert(numpro, 'end', numchamp, text="Fenêtre = " + str(window) + significationWindow, open=False)
                var_idchamp += 1

                a = "       Somme de contrôle = " + str(checksumTcp) + "\n"
                f_res.write(a)
                numchamp = "", numpro, "champ", var_idchamp
                arbre.insert(numpro, 'end', numchamp, text="Somme de contrôle = " + str(checksumTcp), open=False)
                var_idchamp += 1

                a = "       Urgent Pointer = " + str(urgentpointer) + "\n"
                f_res.write(a)
                numchamp = "", numpro, "champ", var_idchamp
                arbre.insert(numpro, 'end', numchamp, text="Urgent Pointer = " + str(urgentpointer), open=False)
                var_idchamp += 1

                a = "       Options = \n"
                f_res.write(a)
                numchamp = "", numpro, "champ", var_idchamp
                arbre.insert(numpro, 'end', numchamp, text="Options ", open=False)
                var_idchamp += 1
                for n in range(len(optionTCP)):
                    a = "           " + str(optionTCP[n]) + "\n"
                    f_res.write(a)
                    numopt = "", numpro, "champ", var_idchamp, n
                    arbre.insert(numchamp, 'end', numopt, text=str(optionTCP[n]), open=False)

                # requete http
                if destinationport == "0050":
                    methode = retirerChampHTTP(liste, "20")
                    URL = retirerChampHTTP(liste, "20")
                    version = retirerChampHTTP(liste, "0d0a")
                    nomchamp = []
                    valeurchamp = []
                    codeRequete = "vide"
                    while i + 3 < len(liste):
                        mot = liste[i] + liste[i + 1] + liste[i + 2] + liste[i + 3]
                        if mot != "0d0a" and mot != "0D0A":
                            nom = retirerChampHTTP(liste, "20")
                            nomchamp.append(nom)
                            valeur = retirerChampHTTP(liste, "0d0a")
                            valeurchamp.append(valeur)
                        else:
                            i = i + 4
                            codeRequete = retirerchamp(liste, len(liste) - i)
                            break

                    a = "   Entête HTTP\n"
                    f_res.write(a)
                    numpro = "", id_trame, "pr", var_idpro
                    var_idpro += 1
                    arbre.insert(id_trame, 'end', numpro, text="Entête HTTP", open=True)

                    a = "       Méthode: " + str(methode) + "\n"
                    f_res.write(a)
                    numchamp = "", numpro, "champ", var_idchamp
                    arbre.insert(numpro, 'end', numchamp, text="Méthode: " + str(methode), open=False)
                    var_idchamp += 1

                    a = "       URL: " + str(URL) + "\n"
                    f_res.write(a)
                    numchamp = "", numpro, "champ", var_idchamp
                    arbre.insert(numpro, 'end', numchamp, text="URL: " + str(URL), open=False)
                    var_idchamp += 1

                    a = "       Version: " + str(version) + "\n"
                    f_res.write(a)
                    numchamp = "", numpro, "champ", var_idchamp
                    arbre.insert(numpro, 'end', numchamp, text="Version: " + str(version), open=False)
                    var_idchamp += 1

                    for n in range(len(nomchamp)):
                        a = "       " + str(nomchamp[n]) + ": " + str(valeurchamp[n]) + "\n"
                        f_res.write(a)
                        numchamp = "", numpro, "champ", var_idchamp
                        arbre.insert(numpro, 'end', numchamp, text=str(nomchamp[n]) + ": " + str(valeurchamp[n]),
                                     open=False)
                        var_idchamp += 1

                    a = "       Corps de la requête: " + str(codeRequete) + "\n"
                    f_res.write(a)
                    numchamp = "", numpro, "champ", var_idchamp
                    arbre.insert(numpro, 'end', numchamp, text="Corps de la requête: " + str(codeRequete), open=False)
                    var_idchamp += 1

                # reponses http
                if sourceport == "0050":
                    version = retirerChampHTTP(liste, "20")
                    codeStatut = retirerChampHTTP(liste, "20")
                    message = retirerChampHTTP(liste, "0d0a")
                    nomchamp = []
                    valeurchamp = []
                    codeReponse = "vide"
                    while i + 3 < len(liste):
                        mot = liste[i] + liste[i + 1] + liste[i + 2] + liste[i + 3]
                        if mot != "0d0a" and mot != "0D0A":
                            nom = retirerChampHTTP(liste, "20")
                            nomchamp.append(nom)
                            valeur = retirerChampHTTP(liste, "0d0a")
                            valeurchamp.append(valeur)
                        else:
                            i = i + 4
                            codeReponse = retirerchamp(liste, len(liste) - i)
                            break

                    a = "   Entête HTTP\n"
                    f_res.write(a)
                    numpro = "", id_trame, "pr", var_idpro
                    var_idpro += 1
                    arbre.insert(id_trame, 'end', numpro, text="Entête HTTP", open=True)

                    a = "       Version: " + str(version) + "\n"
                    f_res.write(a)
                    numchamp = "", numpro, "champ", var_idchamp
                    arbre.insert(numpro, 'end', numchamp, text="Version: " + str(version), open=False)
                    var_idchamp += 1

                    a = "       Code statut: " + str(codeStatut) + "\n"
                    f_res.write(a)
                    numchamp = "", numpro, "champ", var_idchamp
                    arbre.insert(numpro, 'end', numchamp, text="Code statut: " + str(codeStatut), open=False)
                    var_idchamp += 1

                    a = "       Message: " + str(message) + "\n"
                    f_res.write(a)
                    numchamp = "", numpro, "champ", var_idchamp
                    arbre.insert(numpro, 'end', numchamp, text="Message: " + str(message), open=False)
                    var_idchamp += 1

                    for n in range(len(nomchamp)):
                        a = "       " + str(nomchamp[n]) + ": " + str(valeurchamp[n]) + "\n"
                        f_res.write(a)
                        numchamp = "", numpro, "champ", var_idchamp
                        arbre.insert(numpro, 'end', numchamp, text=str(nomchamp[n]) + ": " + str(valeurchamp[n]),
                                     open=False)
                        var_idchamp += 1
                    a = "       Corps de la réponse: " + str(codeReponse) + "\n"
                    f_res.write(a)
                    numchamp = "", numpro, "champ", var_idchamp
                    arbre.insert(numpro, 'end', numchamp, text="Corps de la réponse: " + str(codeReponse), open=False)
                    var_idchamp += 1

    f_res.close()
    arbre.pack(side='left', fill="both", expand=True)
    sb = tkinter.Scrollbar(fenetre, orient=tkinter.VERTICAL, command=arbre.yview)
    sb.pack(side='right', fill='y')
    arbre.configure(yscrollcommand=sb.set)
    fenetre.mainloop()


# tests
i = 0
trames()
analyseur()









