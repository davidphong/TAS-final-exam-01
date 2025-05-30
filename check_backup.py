#!/usr/bin/env python3
import os
import json

def check_backup():
    backup_path = os.path.join('static', 'backups', 'backup.bak')
    
    if not os.path.exists(backup_path):
        print(f"ERROR: Backup file does not exist at {backup_path}")
        return False
    
    try:
        with open(backup_path, 'r') as f:
            data = json.load(f)
            
        if not data or not isinstance(data, list):
            print(f"ERROR: Backup file exists but has invalid format")
            return False
            
        print(f"SUCCESS: Backup file exists at {backup_path}")
        print(f"Found {len(data)} user records in backup")
        
        # Display all usernames in backup
        usernames = [user.get('username') for user in data]
        print(f"\nUsernames in backup: {', '.join(usernames)}")
        
        # Check if the flag user is in the backup
        flag_user = next((user for user in data if user.get('username') == 'flag'), None)
        if flag_user:
            print("\nFlag user found in backup:")
            print(json.dumps(flag_user, indent=2))
        else:
            print("\nWARNING: Flag user not found in backup!")
            
        # Check if the admin user is in the backup
        admin_user = next((user for user in data if user.get('username') == 'admin'), None)
        if admin_user:
            print("\nAdmin user found in backup:")
            print(json.dumps(admin_user, indent=2))
        else:
            print("\nWARNING: Admin user not found in backup!")
            
        return True
    except Exception as e:
        print(f"ERROR: Failed to read backup file: {str(e)}")
        return False

if __name__ == "__main__":
    check_backup() 