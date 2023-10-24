from offchain.KeyTracker_ import InvalidAddress, KeyTracker
import re
import json

def get_pkh_list(contract, privilege_level):
    contract_pkh = str(contract.getPKHsByPrivilege(privilege_level))
    # gonna need some kind of wait / delay here for primetime
    print(contract_pkh)
    contract_pkh_list = re.findall(r'0x[a-fA-F0-9]+', contract_pkh)
    pkh_list = [pkh for pkh in contract_pkh_list]  # Removing '0x' prefix
    contract_pkh_string = json.dumps(contract_pkh)
    contract_pkh_list = json.dumps(contract_pkh_string)
    return pkh_list

def load_two_masters(self, pkhs, filename):
    pkh_index = 0
    master1_loaded = False
    master2_loaded = False

    while not master1_loaded and pkh_index < len(pkhs):
        try:
            key_tracker1 = self.k1.load(filename, pkhs[pkh_index])
            print(f"Load successful for Master 1, PKH: {pkhs[pkh_index]}")
            master1_loaded = True
            pkh_index += 1  # increment the pkh_index after successful load
        except InvalidAddress:
            print(f"No valid keys found for Master 1, PKH: {pkhs[pkh_index]}")
            pkh_index += 1  # increment the pkh_index if load failed

    if not master1_loaded:
        print("Load failed for all provided PKHs for Master 1")
        return

    while not master2_loaded and pkh_index < len(pkhs):
        try:
            key_tracker2 = self.k2.load(filename, pkhs[pkh_index])
            print(f"Load successful for Master 2, PKH: {pkhs[pkh_index]}")
            master2_loaded = True
            pkh_index += 1  # increment the pkh_index after successful load
        except InvalidAddress:
            print(f"No valid keys found for Master 2, PKH: {pkhs[pkh_index]}")
            pkh_index += 1  # increment the pkh_index if load failed

    if not master2_loaded:
        print("Load failed for all provided PKHs for Master 2")

def load_keys(self, pkhs, filename):
    for pkh in pkhs:
        try:
            key_tracker = self.k3.load(filename, pkh)
            print(f"Load successful for PKH: {pkh}")
            return  # Exit function after successful load
        except InvalidAddress:
            print(f"No valid keys found for PKH: {pkh}")
            continue  # Try the next pkh if this one fails
    print("Load failed for all provided PKHs")
