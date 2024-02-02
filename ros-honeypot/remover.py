import os
from datetime import datetime, timedelta
from logging import getLogger

log = getLogger()


def remove_old_pcaps():
    directory = os.path.join("/", "root", "ros-honeypot", "data")
    for filename in os.listdir(directory):
        f = os.path.join(directory, filename)
        if not os.path.isfile(f):
            continue

        try:
            filename = filename.split(".")[0]
            ymd = datetime.now()
            ymd_filename = datetime.strptime(filename, "%Y-%m-%d")
            if ymd - ymd_filename >= timedelta(days=1):
                os.remove(f)
        except Exception as e:
            log.warning(
                f"Failed to remove {f}: {e}",
            )
            continue


if __name__ == "__main__":
    remove_old_pcaps()
