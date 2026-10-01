import subprocess


def ping_host(host: str) -> None:
    command = f"ping -c 1 {host}"

    subprocess.run(
        command,
        shell=True
    )


def calculate(expression: str):
    return eval(expression)


if __name__ == "__main__":
    # Deliberately insecure examples for static-analysis testing.
    ping_host("127.0.0.1")
    print(calculate("2 + 2"))