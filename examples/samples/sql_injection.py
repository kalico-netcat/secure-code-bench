def find_user(connection, user_input):
    query = "SELECT * FROM users WHERE name = '" + user_input + "'"
    return connection.execute(query)
