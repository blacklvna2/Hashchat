import subprocess
import time

def launch_program(command):
    return subprocess.Popen(f"start cmd /k {command}", shell=True)

if __name__ == "__main__":
    # Lancer le serveur
    server_process = launch_program("python Python/server.py")
    time.sleep(1)

    # Lancer le proxy
    proxy_process = launch_program("python Python/proxy.py")
    time.sleep(1)

    # Lancer deux instances du client
    client1_process = launch_program("python Python/client.py")
    client2_process = launch_program("python Python/client.py")

    # Attendre que les processus se terminent
    server_process.wait()
    proxy_process.wait()
    client1_process.wait()
    client2_process.wait()