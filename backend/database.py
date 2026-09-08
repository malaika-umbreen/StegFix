import mysql.connector
import json
from config import DB_HOST, DB_USER, DB_PASSWORD, DB_NAME



# -----------------------------
# Database Connection
# -----------------------------

def get_connection():

    try:

        connection = mysql.connector.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME
        )

        return connection

    except mysql.connector.Error as err:

        print("Database connection error:", err)
        return None


# -----------------------------
# Insert Flow Record
# -----------------------------

def insert_flow(flow_data):

    conn = get_connection()

    if conn is None:
        return

    cursor = conn.cursor()

    query = """
    INSERT INTO flows
    (src_ip, dst_ip, src_port, dst_port, protocol, features, binary_label, technique_label, timestamp)
    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,NOW())
    """

    try:

        cursor.execute(query, (

            flow_data["src_ip"],
            flow_data["dst_ip"],
            flow_data["src_port"],
            flow_data["dst_port"],
            flow_data["protocol"],
            flow_data["features"],
            flow_data["binary_label"],
            flow_data["technique_label"]

        ))

        conn.commit()

        # ✅ Return the inserted flow's ID so we can link detection_log and alert
        return cursor.lastrowid

    except Exception as err:

        print("Insert error:", err)
        return None

    finally:

        cursor.close()
        conn.close()


# -----------------------------
# Insert Detection Log         ← NEW
# -----------------------------

def insert_detection_log(flow_id, src_ip, dst_ip, protocol, technique, risk, confidence, status):

    conn = get_connection()

    if conn is None:
        return

    cursor = conn.cursor()

    query = """
    INSERT INTO detection_logs
    (flow_id, source, dest, protocol, technique, risk, confidence, status)
    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
    """

    try:

        cursor.execute(query, (
            flow_id,
            src_ip,
            dst_ip,
            protocol,
            technique,
            risk,
            confidence,
            status
        ))

        conn.commit()

    except Exception as err:

        print("Insert detection_log error:", err)

    finally:

        cursor.close()
        conn.close()


# -----------------------------
# Insert Alert                 ← NEW
# -----------------------------

def insert_alert(flow_id, src_ip, technique, confidence, severity):

    conn = get_connection()

    if conn is None:
        return

    cursor = conn.cursor()

    message = f"ALERT: {technique} detected from {src_ip} with {confidence}% confidence"

    query = """
    INSERT INTO alerts
    (flow_id, message, severity)
    VALUES (%s, %s, %s)
    """

    try:

        cursor.execute(query, (
            flow_id,
            message,
            severity
        ))

        conn.commit()

    except Exception as err:

        print("Insert alert error:", err)

    finally:

        cursor.close()
        conn.close()


# -----------------------------
# Fetch Flows for Dashboard
# -----------------------------

def get_flows():

    conn = get_connection()

    if conn is None:
        return []

    cursor = conn.cursor(dictionary=True)

    query = """
    SELECT *
    FROM flows
    ORDER BY timestamp DESC
    LIMIT 5000
    """

    try:

        cursor.execute(query)

        results = cursor.fetchall()

        return results

    except mysql.connector.Error as err:

        print("Fetch error:", err)

        return []

    finally:

        cursor.close()
        conn.close()


# -----------------------------
# Fetch Flows by Protocol
# -----------------------------

def get_flows_by_protocol(protocol: str):

    conn = get_connection()

    if conn is None:
        return []

    cursor = conn.cursor(dictionary=True)

    query = """
    SELECT *
    FROM flows
    WHERE protocol = %s
    ORDER BY timestamp DESC
    LIMIT 5000
    """

    try:
        cursor.execute(query, (protocol,))
        return cursor.fetchall()

    except mysql.connector.Error as err:
        print("Fetch error:", err)
        return []

    finally:
        cursor.close()
        conn.close()