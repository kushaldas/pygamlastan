"""Supervise Gunicorn and the recovery worker as one container service."""
import signal
import subprocess
import sys
import time


def main(argv=None):
    """Start both processes, forward shutdown, and exit if either process stops."""
    command = sys.argv[1:] if argv is None else argv
    children = []
    stopping = False
    exit_code = 0

    def stop(signum, frame):
        """Request shutdown; the finally block terminates and reaps both children."""
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        children.append(subprocess.Popen([sys.executable, "manage.py", "idp_recovery_worker"]))
        children.append(subprocess.Popen(command))
        while not stopping:
            for child in children:
                status = child.poll()
                if status is not None:
                    # An unexpected clean exit is still a service failure. This
                    # lets the container restart policy restart both components.
                    exit_code = status if status > 0 else 1
                    stopping = True
                    break
            if not stopping:
                time.sleep(.2)
    finally:
        for child in children:
            if child.poll() is None:
                child.terminate()
        for child in children:
            try:
                child.wait(timeout=20)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
