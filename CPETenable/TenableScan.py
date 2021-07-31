from tenable.sc import TenableSC
import time
import re
from ElementsAPI.ElementsAPI import ElementsAPI



class Scanner_obj(object):

    def __init__(self, sc, scan_id, bad_ports):
        """
        This creates the object represents a tenable scan instance for a specific CPE device. Created when running TenableScanner.scan_device(mac).
        :param sc: tenable.sc api instance
        :param scan_id:
        :param bad_ports: list of unwanted open ports
        """
        self.sc = sc
        self.scan_id = scan_id
        self.safe = True
        self.vulns = []
        self.ports = []
        self.error = False
        self.complete = False
        self.bad_ports = bad_ports


    def wait_for_results(self):
        """
        When this method is called on a Scanner_obj it lauches a scan and then saves result om the Scammer_obj
        """
        sc = self.sc
        running = sc.scans.launch(self.scan_id)
        while True:
            time.sleep(30)
            status = sc.scan_instances.details(running['scanResult']['id'], fields=['status'])
            if status['status'] == "Error":
                sc.scans.delete(self.scan_id)
                self.error = True
                self.complete = True
                return
            if status['status'] == 'Completed':
                time.sleep(15)
                break
            print("running")

        id = int(running['scanResult']['id'])

        vulns = sc.analysis.scan(id,('severity', '>=', '4'), ('exploitAvailable', '=', 'true'), tool='sumip')

    

        ports = sc.analysis.scan(id, tool='sumport')
        for port in ports:
            port = port["port"]
            if port in self.bad_ports:
                self.ports.append(port)
                self.safe = False
        if any(True for _ in vulns):
            self.safe = False
        sc.scans.delete(self.scan_id)
        sc.logout()
        self.complete = True
        self.vulns = list(vulns)

    def get_vulns(self):
        """
        Returns a list of all the high and critical vulnerabilities on the device as well as a list ofprohibited open ports based on ports in badPorts.txt. 
        The list is empty if none exist. If the scan ends in an error a list with the string "Scan IPs are not within
        your accessible range" is returned. If this method is called before wait for results a list containing "Scan not launched" is returned.  
        """
        
        if self.complete:
            if self.error:
                return ["Scan IPs are not within your accessible range."]
            else:
                return {'Vulnerabilities: ':self.vulns, 'Ports:': self.ports }
        else:
            return ["Scan not launched"]

    def get_safe(self):
        if self.error:
            return "Error"
        else:
            return self.safe


class TenableScanner(object):

    """ Plume API Python Object"""

    def __init__(self, secret_key_sec: str, secret_key_adm: str, access_key_sec: str, access_key_adm: str, host: str, pid: str, password: str, bad_ports: list):
        """
        This creates the object that will create a scan instance for the device with the specified information.
        Example Instantiation:
        test = TenableScanner("redacted", "redacted", "redacted", "redacted", "98.8.46.130", "P1234567", "password")
        :param secret_key_sec:
        :param secret_key_adm:
        :param access_key_sec:
        :param access_key_adm:
        :param host:
        :param pid:
        :param password:
        :param bad_ports: A list of unwanted open ports
        """

        self.secret_key_sec =  secret_key_sec
        self.secret_key_adm = secret_key_adm
        self.access_key_sec = access_key_sec
        self.access_key_adm = access_key_adm
        self.pid = pid
        self.password = password
        self.host = host
        self.bad_ports = bad_ports

    class DeviceNotFoundException(Exception):
        pass

    def scan_device(self, mac: str):
        """
        This method creates a scan using the given an intialized tenableScanner object and mac addresss.

        :param mac:
        :returns: scanner_obj which can be used to launch the scan and get results

        Ussage: 
        scanner_obj = tenable.scan_device(dead.beef.coffee)
        """

        elements = ElementsAPI('https://elements.charter.com/',self.pid,self.password,0)
        data = elements.dlpqs_lookup(mac)
        error = None
        try:
            lease = data['response']['response']['data'][0]
        except KeyError:
            error = TenableScanner.DeviceNotFoundException(f"{mac} was not found")

        if error:
        # We throw it out here to prevent a double exception... Those are annoying to read!
            raise error

        for key in lease:
            if key == 'ip':
                ip = lease[key]
            if key == 'provisioning':
                for subkey in lease[key]:
                    if subkey == 'region':
                        region = lease[key][subkey]
        elements.logout()
        repo = 5
        pat = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
        if pat.match(ip):
            repo = 4
        scanners = {'8':47, "bufrga":48, "blngmt":44, '6':44, '1':51, '2':46, '3':46, "renonv": 63, "grhvmi":53,  '4':59}
        sc = TenableSC(self.host)
        sc.login(access_key=self.access_key_adm, secret_key=self.secret_key_adm)

        sc.repositories.edit(repo, allowed_ips=[ip])
        try:
            zone = scanners[region]
        except KeyError:
            print("Device location is not currently supported")
            exit()
        sc.scan_zones.edit(scanners[region],ips=[ip])
        sc.logout()
        sc.login(access_key=self.access_key_sec, secret_key=self.secret_key_sec)
        res = sc.scans.create('API Scan', repo, policy_id=1000001, targets=[ip])
        scan_obj = Scanner_obj(sc, res['id'], self.bad_ports)
        time.sleep(5)
        return scan_obj



    


