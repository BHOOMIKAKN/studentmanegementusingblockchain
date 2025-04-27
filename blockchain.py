import hashlib
import json
from datetime import datetime

class Block:
    def __init__(self, index, previous_hash, student_data=None, staff_data=None):
        self.index = index
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.previous_hash = previous_hash
        self.student_data = student_data or {}  # Default to empty if not provided
        self.staff_data = staff_data  # Optional field for staff data
        self.certificates = []  # New attribute to store certificates
        self.hash = self.calculate_hash()  # Call to calculate_hash() after initializing attributes

    def calculate_hash(self):
        # Create the string for the block, excluding the hash itself
        block_string = json.dumps({
            'index': self.index,
            'timestamp': self.timestamp,
            'student_data': self.student_data,
            'staff_data': self.staff_data,  # Include staff_data in the hash calculation
            'previous_hash': self.previous_hash
        }, sort_keys=True)  # Sort keys for consistent hashing
        return hashlib.sha256(block_string.encode()).hexdigest()

    def to_dict(self):
        return {
            'index': self.index,
            'timestamp': self.timestamp,
            'student_data': self.student_data,
            'staff_data': self.staff_data,
            'previous_hash': self.previous_hash,
            'hash': self.hash
        }



class Blockchain:
    def __init__(self):
        self.chain = []
        # Create the genesis block
        self.create_block(previous_hash='0', data={'message': 'Genesis Block'})

    def create_block(self, previous_hash, data):
        block = Block(index=len(self.chain), previous_hash=previous_hash, student_data=data, staff_data=data)
        self.chain.append(block)
        return block



    def get_latest_block(self):
        return self.chain[-1] if self.chain else None

    def get_data_by_key(self, key, value):
        """
        Fetch data from the blockchain by a specific key-value pair.
        :param key: The key to search for (e.g., 'usn' or 'email').
        :param value: The value to match for the key.
        :return: Data if found, otherwise None.
        """
        for block in self.chain:
            if block.data.get(key) == value:
                return block.data
        return None  # Return None if no matching data is found


class StudentBlockchain(Blockchain):
    def add_student(self, student_data):
        latest_block = self.get_latest_block()
        previous_hash = latest_block.hash if latest_block else '0'
        return self.create_block(previous_hash, student_data)

    def get_student_by_usn(self, usn):
        return self.get_data_by_key('usn', usn)

    def add_block(self, block):
        self.chain.append(block)

class StaffBlockchain(Blockchain):
    def add_staff(self, staff_data):
        latest_block = self.get_latest_block()
        previous_hash = latest_block.hash if latest_block else '0'
        return self.create_block(previous_hash, staff_data)

    def get_all_staff_details(self):
        staff_list = []
        for block in self.chain:
            if block.staff_data:
                staff_list.append({
                    "serial_number": block.staff_data.get("serial_number"),
                    "name": block.staff_data.get("name"),
                    "phone_number": block.staff_data.get("phone_number"),
                    "branch": block.staff_data.get("branch"),
                    "email": block.staff_data.get("email"),
                    "timestamp": block.timestamp,
                    "previous_hash": block.previous_hash,
                    "current_hash": block.hash
                })

        return staff_list

class AssignmentBlockchain(Blockchain):
    def add_assignment(self, assignment_data):
        """
        Adds assignment data to the blockchain.
        :param assignment_data: Dictionary containing the assignment details.
        """
        latest_block = self.get_latest_block()
        previous_hash = latest_block.hash if latest_block else '0'
        return self.create_block(previous_hash, assignment_data)

    def get_assignments_by_branch(self, branch):
        """
        Fetch all assignments by a specific branch.
        :param branch: The branch to filter assignments.
        :return: List of assignments belonging to the specified branch.
        """
        assignments_list = []
        for block in self.chain:
            if block.student_data and block.student_data.get("branch") == branch:
                assignments_list.append({
                    "date": block.student_data.get("date"),
                    "branch": block.student_data.get("branch"),
                    "subject": block.student_data.get("subject"),
                    "work": block.student_data.get("work"),
                    "due_date": block.student_data.get("due_date"),
                    "timestamp": block.timestamp,
                    "previous_hash": block.previous_hash,
                    "current_hash": block.hash
                })

        return assignments_list
