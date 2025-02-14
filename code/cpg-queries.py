import os

# Path to the directory containing the CSV files
schema_dir = "/home/umd-user/joern/projectcpg/code/db/schemas"

# Check if the directory exists
if os.path.exists(schema_dir) and os.listdir(schema_dir):
    for file_name in os.listdir(schema_dir):
        file_path = os.path.join(schema_dir, file_name)
        
        # Check if it is a CSV file
        if file_name.endswith(".csv") and os.path.isfile(file_path):
            try:
                # Open the file in write mode to clear its contents
                with open(file_path, 'w') as csv_file:
                    pass  # Writing nothing clears the file
                print(f"Cleared contents of file: {file_path}")
            except Exception as e:
                print(f"Failed to clear contents of file {file_name}: {e}")
else:
    print(f"Schema directory does not exist or is empty: {schema_dir}")
