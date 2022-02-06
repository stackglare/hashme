import hashlib
import argparse

version = "1.0.0"

def hash_string(st, hash_alg):
    if hash_alg == "sha256":
        hashobj = hashlib.sha256(bytes(st, "utf-8"))
        return hashobj
    elif hash_alg == "sha512":
        hashobj = hashlib.sha512(bytes(st, "utf-8"))
        return hashobj
    elif hash_alg == "md5":
        hashobj = hashlib.md5(bytes(st, "utf-8"))
        return hashobj
    else:
        return False


def print_version(args):
    print(version)

def compare(args):
    if args.hash_1 == args.hash_2:
        print("Match: True")
    else:
        print("Match: False")

def compare_files(args):
    file_1_hashobj = None;
    file_2_hashobj = None;

    with open(args.path_1, "r") as file_1:
        file_1_hashobj = hash_string(file_1.read(), args.hash_alg)
        with open(args.path_2, "r") as file_2:
            file_2_hashobj = hash_string(file_2.read(), args.hash_alg)
    
    if file_1_hashobj:
        file_1_hexdigest = file_1_hashobj.hexdigest()
        file_2_hexdigest = file_2_hashobj.hexdigest()

        if args.verbose:
            if file_1_hexdigest == file_2_hexdigest:
                print("Match: True")
            else:
                print("Match: False")
            print("\nHashes of " + args.path_1 + " and " + args.path_2 + " respectively:\n" + file_1_hexdigest + "\n" + file_2_hexdigest)
        else:
            if file_1_hexdigest == file_2_hexdigest:
                print("Match: True")
            else:
                print("Match: False")

def hash(args):
    hashobj = hash_string(args.string, args.hash_alg)
    if hashobj:
        print(hashobj.name.upper() + ": " + hashobj.hexdigest())
    else:
        print("The provided hash algorithm is not valid")

def hash_file(args):
    with open(args.path, "r") as file:
        hashobj = hash_string(file.read(), args.hash_alg)
        if hashobj:
            print(hashobj.name.upper() + ": " + hashobj.hexdigest())
        else:
            print("The provided hash algorithm is not valid")

def verify(args):
    with open(args.path, "r") as file:
        hashobj = hash_string(file.read(), args.hash_alg)
        if hashobj:
            if hashobj.hexdigest() == args.hash:
                print("Match: True")
            else:
                print("Match: False")
        else:
            print("The provided hash algorithm is not valid")
    

parser = argparse.ArgumentParser(description="Utilities for hashing")
parser.add_argument("-v", "--verbose", action="store_true",)
subparsers = parser.add_subparsers()

subparsers_compare = subparsers.add_parser("version", help="Displays the current version")
subparsers_compare.set_defaults(func=print_version)

subparsers_compare = subparsers.add_parser("compare", help="Compares two hashes against each other")
subparsers_compare.add_argument("hash_1")
subparsers_compare.add_argument("hash_2")
subparsers_compare.set_defaults(func=compare)

subparsers_compare_files = subparsers.add_parser("comparefiles", help="Compares the hashes of two files against each other")
subparsers_compare_files.add_argument("path_1")
subparsers_compare_files.add_argument("path_2")
subparsers_compare_files.add_argument("hash_alg")
subparsers_compare_files.set_defaults(func=compare_files)

subparsers_hash = subparsers.add_parser("hash", help="Hashes a string with the provided hash algorithm")
subparsers_hash.add_argument("string")
subparsers_hash.add_argument("hash_alg")
subparsers_hash.set_defaults(func=hash)

subparsers_hash_file = subparsers.add_parser("hashfile", help="Hashes a file with the provided hash algorithm")
subparsers_hash_file.add_argument("path")
subparsers_hash_file.add_argument("hash_alg")
subparsers_hash_file.set_defaults(func=hash_file)

subparsers_verify = subparsers.add_parser("verify", help="Verifies the hash of a given file")
subparsers_verify.add_argument("path")
subparsers_verify.add_argument("hash")
subparsers_verify.add_argument("hash_alg")
subparsers_verify.set_defaults(func=verify)

args = parser.parse_args()
if "func" in args:
    args.func(args)