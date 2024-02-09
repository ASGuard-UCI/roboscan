import concurrent.futures
import logging
import os
import re
import subprocess
import zlib
from datetime import datetime, timedelta
from urllib.parse import quote

import mysql.connector
import requests_cache
from dotenv import load_dotenv
from requests.exceptions import HTTPError
from scapy.all import *

logging.basicConfig(
    filename="output.log",
    encoding="utf-8",
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s: %(message)s",
)

load_dotenv()

HONEYPOT_IPS = {
    "3.19.252.184": "172.31.30.249",  # AWS Ohio
    "54.232.68.11": "172.31.34.248",  # AWS Sao Paulo
    "13.41.212.74": "172.31.9.238",  # AWS London
    "157.175.27.235": "172.31.4.190",  # AWS Bahrain
    "13.246.60.122": "172.31.12.15",  # AWS Cape Town
    "18.181.153.25": "172.31.5.210",  # AWS Tokyo
    "15.207.225.52": "172.31.1.40",  # AWS Mumbai
    "54.169.42.77": "172.31.27.233",  # AWS Singapore
    "18.101.148.182": "172.31.44.146",  # AWS Spain
    "35.225.206.55": "10.128.0.2",  # GCP Iowa
    "34.88.3.61": "10.166.0.2",  # GCP Finland
    "35.189.27.27": "10.152.0.3",  # GCP Sydney
    "35.220.204.18": "10.170.0.2",  # GCP Hong Kong
    "34.18.58.229": "10.212.0.2",  # GCP Doha
    "20.163.25.107": "10.0.0.4",  # Azure Arizona
    "4.206.220.35": "10.0.0.4",  # Azure Toronto
    "20.174.33.127": "10.0.0.4",  # Azure Dubai
    "18.61.113.51": "172.31.24.175",  # AWS Hyderabad
    "52.10.234.47": "172.31.19.173",  # AWS Oregon
    "3.39.103.121": "172.31.44.168",  # AWS Seoul
    "18.102.109.52": "172.31.39.206",  # AWS Milan
    "108.137.136.67": "172.31.2.164",  # AWS Jakarta
    "16.51.95.203": "172.31.19.175",  # AWS Melbourne
    "18.193.239.21": "172.31.16.125",  # AWS Frankfurt
    "51.20.215.250": "172.31.24.84",  # AWS Stockholm
    "54.219.16.75": "172.31.10.250",  # AWS Northern California
    "34.176.109.131": "10.194.0.2",  # GCP Santiago
    "34.174.110.171": "10.206.0.2",  # GCP Dallas
    "34.131.168.12": "10.190.0.2",  # GCP Delhi
    "34.116.169.242": "10.186.0.2",  # GCP Warsaw
    "34.140.239.55": "10.132.0.2",  # GCP Belgium
    "34.102.105.118": "10.168.0.2",  # GCP Los Angeles
    "20.39.241.201": "10.0.0.4",  # Azure Paris
    "20.224.64.111": "10.0.0.4",  # Azure Netherlands
    "102.37.147.249": "10.0.0.4",  # Azure Johannesburg
    "20.208.128.89": "10.0.0.4",  # Azure Switzerland
    "51.120.245.48": "10.0.0.4",  # Azure Norway
    "4.240.83.130": "10.0.0.4",  # Azure Central India
}

# Cache requests to AbuseIPDB to ensure we don't go over rate limits
session = requests_cache.CachedSession(
    "abuseIPDB_cache", expire_after=timedelta(days=1)
)


def ping_honeypots(username, password):
    """
    Retrieve new data from PCAP files with rsync, then upload each packet's
    metadata and payload to a MySQL database.

    :param str username: The username of the MySQL database to insert into
    :param str password: The password of the MySQL database to insert into
    """

    if not username or not password:
        raise Exception("Username and password are required!")

    now = datetime.now()

    # Establish MySQL connection
    connection = mysql.connector.pooling.MySQLConnectionPool(
        pool_size=32,
        user=username,
        password=password,
        host="127.0.0.1",
        database="mysql",
    )
    connection2 = mysql.connector.pooling.MySQLConnectionPool(
        pool_size=32,
        user=username,
        password=password,
        host="127.0.0.1",
        database="mysql",
    )

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=10
    ) as executor:
        futures = []
        for honeypot, private_ip in HONEYPOT_IPS.items():
            futures.append(
                executor.submit(
                    _process_honeypot,
                    honeypot=honeypot,
                    private_ip=private_ip,
                    connections=[connection, connection2],
                    now=now,
                )
            )
        for future in concurrent.futures.as_completed(futures):
            print(future.result())


def get_ip_data(ip):
    """
    Fetch data about the provided IP including location and the API's abuse
    confidence score, using a cache that expires after a day to remain below
    API rate limits.

    :param str ip: The IP to query using the AbuseIPDB
    """

    try:
        response = session.get(
            f"https://api.abuseipdb.com/api/v2/check?ipAddress={quote(ip)}",
            headers={"Key": os.getenv("ABUSEIPDB_API_KEY")},
        )
        response_json = response.json()

        if response.status_code != 200:
            raise HTTPError
        elif "data" not in response_json:
            raise HTTPError()
        return response_json

    except HTTPError as e:
        logging.warning(f"HTTPError occurred when querying AbuseIPDB: {e}")
        return None


def _process_honeypot(honeypot, private_ip, connections, now):
    """
    Get a connection to the database from the first pooled MySQL connection
    object possible in the provided connections list.

    Pull the PCAP files from the honeypot and parse each one, inserting it into
    the database if its source IP is not the honeypot's private IP.

    In case we receive a ROS 1 payload, it will be gzip encoded, so parse the
    payload for the "Content-Encoding: gzip" header and if it exists, decode
    the payload using gzip.

    :param str honeypot: The public IP of the honeypot
    :param private_ip: The private IP of the honeypot
    :param list[PooledMySQLConnection]: A list of pooled MySQL connections that
        allow threaded processes to access the database
    :param datetime now: The datetime at which this program began execution
    """
    cnx = _get_connection_from_pool(connections)

    ymd_date = now.strftime("%Y-%m-%d")
    logging.info(f"Pinging {honeypot} data for {ymd_date}")
    subprocess.run(
        [
            "rsync",
            "-azv",
            f"root@{honeypot}:/root/ros-honeypot/data",
            f"/home/ubuntu/honeypot_tracker/data/{honeypot}/",
        ]
    )

    files_to_process = _get_files_to_process(honeypot, ymd_date)

    insert_data = []
    for file in files_to_process:
        for packet in rdpcap(file):
            time = float(packet.time)
            timestamp = datetime.fromtimestamp(time)
            src_ip = packet["IP"].src
            src_port = None
            dst_port = None
            flag = ""
            payload = None

            if "TCP" in packet:
                src_port = packet["TCP"].sport
                dst_port = packet["TCP"].dport
                flag = str(packet["TCP"].flags)
                payload = bytes(packet["TCP"].payload)
            elif "UDP" in packet:
                try:
                    src_port = packet["UDP"].sport
                    dst_port = packet["UDP"].dport
                    payload = bytes(packet["UDP"].payload)
                except Exception as e:
                    logging.error(f"Error reading packet in {file}: {e}")
                    continue

            try:
                header_data_sep = payload.index(b"\r\n\r\n")
                http_header = payload[payload.index(b"HTTP/1.1") : header_data_sep + 2]
                if not http_header:
                    raise Exception()
                raw_header = payload[: header_data_sep + 2]
                parsed_header = dict(
                    re.findall(
                        r"(?P<name>.*?): (?P<value>.*?)\r\n", raw_header.decode("utf-8")
                    )
                )
                if parsed_header["Content-Encoding"] == "gzip":
                    http_payload = payload[header_data_sep + 4 :]
                    payload = zlib.decompress(http_payload, 16 + zlib.MAX_WBITS)
            except:
                pass

            not_yet_inserted = _has_been_inserted(
                cnx, timestamp, src_ip, honeypot, flag
            )

            if not_yet_inserted and (
                (private_ip is None and src_ip != honeypot)
                or (private_ip is not None and src_ip != private_ip)
            ):
                abuseipdb_data = get_ip_data(src_ip)
                region = None
                abuse_confidence_score = None
                if abuseipdb_data is not None:
                    region = abuseipdb_data["data"]["countryCode"]
                    abuse_confidence_score = abuseipdb_data["data"][
                        "abuseConfidenceScore"
                    ]
                data = (
                    src_ip,
                    datetime.strftime(timestamp, "%Y-%m-%d %H:%M:%S.%f"),
                    honeypot,
                    src_port,
                    flag,
                    payload,
                    abuse_confidence_score,
                    region,
                    dst_port in (7400, 7401),
                )
                insert_data.append(data)
                logging.info(f"Discovered {src_ip} on port {src_port} at {timestamp}")

    _insert_packets(cnx, insert_data)

    cnx.close()

    logging.info(f"Output for honeypot {honeypot} written to {honeypot}.pcap")


def _get_files_to_process(honeypot, ymd_date):
    path = os.path.join(
        "/", "home", "ubuntu", "honeypot_tracker", "data", honeypot, "data"
    )
    files_to_process = []
    for file in os.listdir(path):
        split = os.path.splitext(file)
        if split[-1] == ".pcap" and split[0].startswith(ymd_date):
            files_to_process.append(os.path.join(path, file))
    return files_to_process


def _get_connection_from_pool(connections):
    cnx = None
    for i in range(len(connections)):
        try:
            cnx = connections[i].get_connection()
            break
        except mysql.connector.errors.PoolError:
            pass
    if cnx is None:
        raise mysql.connector.errors.PoolError()
    return cnx


def _has_been_inserted(cnx, timestamp, src_ip, honeypot, flag):
    cursor = cnx.cursor()
    select = "SELECT packet_timestamp, ip, target_ip, tcp_flag from attacker_ipsv2 WHERE packet_timestamp = %s AND ip LIKE %s AND target_ip LIKE %s AND tcp_flag LIKE %s"
    query_data = (timestamp, src_ip, honeypot, flag)
    cursor.execute(select, query_data)
    res = cursor.fetchall()
    cursor.close()
    if len(res) != 0:
        print("Data:", query_data)
        print("Result:", res)
    return len(res) == 0


def _insert_packets(cnx, insert_data):
    cursor = cnx.cursor()
    insert = "INSERT INTO attacker_ipsv2 (ip, packet_timestamp, target_ip, src_port, tcp_flag, raw_data, abuse_confidence_score, region, is_ros2) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)"
    cursor.executemany(insert, insert_data)
    cnx.commit()
    cursor.close()


if __name__ == "__main__":
    ping_honeypots(os.getenv("USERNAME"), os.getenv("GRAFANA_USER"))
