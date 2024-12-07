# **Core Requirements:**
1. **Count Requests per IP Address**:
    - Parse the provided log file to extract all IP addresses.
    - Calculate the number of requests made by each IP address.
    - Sort and display the results in descending order of request counts.
2. **Identify the Most Frequently Accessed Endpoint**:
    - Extract the endpoints (e.g., URLs or resource paths) from the log file.
    - Identify the endpoint accessed the highest number of times.
    - Provide the endpoint name and its access count.
3. **Detect Suspicious Activity**:
    - Identify potential brute force login attempts by:
        - Searching for log entries with failed login attempts (e.g., HTTP status code `401` or a specific failure message like "Invalid credentials").
        - Flagging IP addresses with failed login attempts exceeding a configurable threshold (default: 10 attempts).
    - Display the flagged IP addresses and their failed login counts.
4. **Output Results**:
    - Display the results in a clear, organized format in the terminal.
    - Save the results to a CSV file named `log_analysis_results.csv` with the following structure:
        - **Requests per IP**: Columns: `IP Address`, `Request Count`
        - **Most Accessed Endpoint**: Columns: `Endpoint`, `Access Count`
        - **Suspicious Activity**: Columns: `IP Address`, `Failed Login Count`

# **Files:**

- [log_analysis.py](log_analysis.py): The Python script for log analysis.
- [sample.log](sample.log): A sample log file used for testing the script.
- [log_analysis_results.csv](log_analysis_results.csv): A log analysis assignment terminal output.

# **Requirements:**

Python 3.x or Google Colaboratory

# **Way to upload sample.log file to Google Colaboratory. Here's how:**

# **Use the File Upload Feature in Colab:**

1. Open your Colab notebook.
2. Run the following code to enable the upload widget:
 
       from google.colab import files
       uploaded = files.upload()

4. This will open a file picker dialog. Select your sample.log file from your local computer.

5. Once uploaded, Colab saves the file in its root directory (/content). You can verify its presence by listing the files:

       !ls

6. Use the file in your script as:
 
       with open('sample.log', 'r') as log_file:
         for line in log_file:
            print(line.strip())





  


  
