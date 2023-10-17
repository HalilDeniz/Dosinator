import pyfiglet
from colorama import init, Fore

# colorama'yı başlat
init(autoreset=True)

def dosinatorfiglet():
    metin = "DosInator..."
    figlet_yazi = pyfiglet.figlet_format(metin, font="slant")


    return print(Fore.GREEN + figlet_yazi)
