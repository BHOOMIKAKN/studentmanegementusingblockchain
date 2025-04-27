import hashlib
import json
import time

# Block structure for the blockchain
class Block:
    def __init__(self, index, previous_hash, student_data, certificate_hash, timestamp=None):
        self.index = index
        self.previous_hash = previous_hash
        self.timestamp = timestamp or time.time()
        self.student_data = student_data
        self.certificate_hash = certificate_hash
        self.hash = None  # The hash will be set later, after all data is finalized

    def calculate_hash(self):
        """
        Calculate the hash for the current block using its contents.
        """
        block_data = {
            "index": self.index,
            "previous_hash": self.previous_hash,
            "timestamp": self.timestamp,
            "student_data": self.student_data,
            "certificate_hash": self.certificate_hash
        }
        block_string = json.dumps(block_data, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

# Blockchain to manage blocks
class Blockchain:
    def __init__(self):
        self.chain = [self.create_genesis_block()]

    def create_genesis_block(self):
        """
        Create the initial (genesis) block in the blockchain.
        """
        genesis_block = Block(0, "0", {"name": "Genesis Block"}, "0")
        genesis_block.hash = genesis_block.calculate_hash()  # Set the hash of the genesis block
        return genesis_block

    def get_latest_block(self):
        """
        Return the last block in the chain.
        """
        return self.chain[-1]

    def add_block(self, student_data, certificate_hash):
        """
        Add a new block to the chain. Ensures the previous hash is set correctly.
        """
        previous_block = self.get_latest_block()

        # Ensure previous block's hash is calculated
        if previous_block.hash is None:
            previous_block.hash = previous_block.calculate_hash()

        new_block = Block(
            index=len(self.chain), 
            previous_hash=previous_block.hash,  # Use the previous block's calculated hash
            student_data=student_data, 
            certificate_hash=certificate_hash
        )

        new_block.hash = new_block.calculate_hash()  # Calculate the block hash after setting all data
        self.chain.append(new_block)
        print(f"Block {new_block.index} added to blockchain.")

    def is_chain_valid(self):
        """
        Check the validity of the blockchain.
        Ensures the hash of each block is correct and all blocks are properly linked.
        """
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]

            # Check if the current block's hash is valid
            if current_block.hash != current_block.calculate_hash():
                print(f"Block {i}'s hash is invalid.")
                return False

            # Check if the previous block's hash matches the current block's previous_hash
            if current_block.previous_hash != previous_block.hash:
                print(f"Block {i} is not properly linked to the previous block.")
                return False

        return True

# Student Ledger to manage student data and certificates
class StudentLedger:
    def __init__(self):
        self.blockchain = Blockchain()

    def add_student(self, student_data, certificate):
        """
        Add a new student and their certificate to the blockchain.
        """
        certificate_hash = self.hash_certificate(certificate)
        self.blockchain.add_block(student_data, certificate_hash)

    def hash_certificate(self, certificate):
        """
        Create a secure hash of the student's certificate.
        """
        return hashlib.sha256(certificate.encode()).hexdigest()

    def validate_certificate(self, student_name, certificate):
        """
        Validate the student's certificate by comparing its hash.
        Checks all blocks in the blockchain for the given student name and certificate.
        """
        certificate_hash = self.hash_certificate(certificate)
        valid = False  # Flag to track if any certificate matches

        # Traverse the blockchain to find all matching students
        for block in self.blockchain.chain:
            if block.student_data.get("name") == student_name:
                if block.certificate_hash == certificate_hash:
                    print(f"Certificate for {student_name} in Block {block.index} is valid.")
                    valid = True
                else:
                    print(f"Certificate for {student_name} in Block {block.index} is invalid.")
        
        if not valid:
            print(f"No valid certificate found for {student_name}.")
        return valid


    def show_all_students(self):
        """
        Display all the students (blocks) present in the blockchain.
        """
        print("All students in the blockchain:")
        for block in self.blockchain.chain:
            print(f"Block {block.index}:")
            print(f"    Student Data: {block.student_data}")
            print(f"    Certificate Hash: {block.certificate_hash}")
            print(f"    Timestamp: {time.ctime(block.timestamp)}")
            print(f"    Previous Hash: {block.previous_hash}")
            print(f"    Current Hash: {block.hash}")
            print("---------------------------------------------------")


# Function to add students dynamically from user input
def add_students_dynamically(ledger):
    """
    Collects student details from user input and adds them to the blockchain.
    """
    while True:
        # Collect student details from the user
        name = input("Enter student name: ")
        student_id = input("Enter student ID: ")
        course = input("Enter student course: ")
        certificate = input("Enter certificate details: ")

        # Create student data dictionary
        student_data = {"name": name, "id": student_id, "course": course}

        # Add the student and their certificate to the blockchain
        ledger.add_student(student_data, certificate)

        # Ask if user wants to add another student
        another = input("Do you want to add another student? (yes/no): ").lower()
        if another != 'yes':
            break


# Sample usage of the system

# Initialize the ledger
ledger = StudentLedger()

# Dynamically add students based on user input
add_students_dynamically(ledger)

# Validate the certificate
student_name = input("Enter student name for certificate validation: ")
certificate = input("Enter certificate to validate: ")
ledger.validate_certificate(student_name, certificate)

# Verify the integrity of the entire blockchain
print("Is blockchain valid?", ledger.blockchain.is_chain_valid())

# Show all the student details (blocks in the blockchain)
ledger.show_all_students()
