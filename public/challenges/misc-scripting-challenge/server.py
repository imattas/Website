#!/usr/bin/env python3
"""
Misc Challenge: Scripting Challenge
A server that asks 100 rapid math questions. Players must answer all
correctly within the time limit to receive the flag.

Can be run as:
  1. A local interactive challenge: python3 server.py
  2. A network service: python3 server.py --serve [port]

Intended solution: Write a script (pwntools, socket, or subprocess)
that connects and solves the math problems automatically.
"""

import random
import time
import sys
import socket
import threading

FLAG = "zemi{4ut0m4t10n_1s_k3y}"

NUM_QUESTIONS = 100
TIME_LIMIT = 30  # seconds total for all questions
OPERATIONS = ["+", "-", "*"]


def generate_question():
    """Generate a random math question with integer answer."""
    op = random.choice(OPERATIONS)
    if op == "+":
        a, b = random.randint(1, 999), random.randint(1, 999)
        answer = a + b
    elif op == "-":
        a = random.randint(100, 999)
        b = random.randint(1, a)  # ensure positive result
        answer = a - b
    else:  # multiplication
        a, b = random.randint(1, 99), random.randint(1, 99)
        answer = a * b
    return f"{a} {op} {b}", answer


def run_challenge_interactive():
    """Run the challenge in interactive (stdin/stdout) mode."""
    print("=" * 50)
    print("  MATH SPEED CHALLENGE")
    print("=" * 50)
    print(f"Answer {NUM_QUESTIONS} math questions in {TIME_LIMIT} seconds.")
    print("All answers are integers.")
    print("=" * 50)
    print()

    random.seed()
    start_time = time.time()
    correct = 0

    for i in range(1, NUM_QUESTIONS + 1):
        elapsed = time.time() - start_time
        remaining = TIME_LIMIT - elapsed

        if remaining <= 0:
            print(f"\n[!] Time's up! You answered {correct}/{NUM_QUESTIONS} correctly.")
            print("[!] Better luck next time!")
            return

        question, answer = generate_question()
        try:
            user_input = input(f"Q{i:3d}/{NUM_QUESTIONS}: {question} = ")
        except EOFError:
            print("\n[!] Connection closed.")
            return

        try:
            user_answer = int(user_input.strip())
        except ValueError:
            print(f"[!] Invalid input. Expected integer. (Answer was {answer})")
            print("[!] Challenge failed!")
            return

        if user_answer != answer:
            print(f"[!] Wrong! {question} = {answer}, not {user_answer}")
            print("[!] Challenge failed!")
            return

        correct += 1

    elapsed = time.time() - start_time
    print()
    print(f"[+] All {NUM_QUESTIONS} questions answered correctly in {elapsed:.2f}s!")
    print(f"[+] FLAG: {FLAG}")


def handle_client(conn, addr):
    """Handle a single client connection."""
    try:
        conn.settimeout(TIME_LIMIT + 5)
        conn.sendall(b"=" * 50 + b"\n")
        conn.sendall(b"  MATH SPEED CHALLENGE\n")
        conn.sendall(b"=" * 50 + b"\n")
        conn.sendall(f"Answer {NUM_QUESTIONS} math questions in {TIME_LIMIT} seconds.\n".encode())
        conn.sendall(b"All answers are integers.\n")
        conn.sendall(b"=" * 50 + b"\n\n")

        random.seed()
        start_time = time.time()

        for i in range(1, NUM_QUESTIONS + 1):
            elapsed = time.time() - start_time
            if elapsed > TIME_LIMIT:
                conn.sendall(b"\n[!] Time's up!\n")
                return

            question, answer = generate_question()
            prompt = f"Q{i:3d}/{NUM_QUESTIONS}: {question} = "
            conn.sendall(prompt.encode())

            data = b""
            while b"\n" not in data:
                chunk = conn.recv(1024)
                if not chunk:
                    return
                data += chunk

            try:
                user_answer = int(data.strip())
            except ValueError:
                conn.sendall(b"[!] Invalid input. Challenge failed!\n")
                return

            if user_answer != answer:
                conn.sendall(f"[!] Wrong! {question} = {answer}\n".encode())
                return

        elapsed = time.time() - start_time
        conn.sendall(f"\n[+] All correct in {elapsed:.2f}s!\n".encode())
        conn.sendall(f"[+] FLAG: {FLAG}\n".encode())

    except (socket.timeout, ConnectionError):
        pass
    finally:
        conn.close()


def run_server(port=9999):
    """Run as a network service."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", port))
    server.listen(5)
    print(f"[*] Listening on 0.0.0.0:{port}")
    print(f"[*] Connect with: nc localhost {port}")

    try:
        while True:
            conn, addr = server.accept()
            print(f"[*] Connection from {addr}")
            t = threading.Thread(target=handle_client, args=(conn, addr))
            t.daemon = True
            t.start()
    except KeyboardInterrupt:
        print("\n[*] Shutting down.")
        server.close()


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--serve":
        port = int(sys.argv[2]) if len(sys.argv) > 2 else 9999
        run_server(port)
    else:
        run_challenge_interactive()


if __name__ == "__main__":
    main()
