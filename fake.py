from faker import Faker
import csv

fake = Faker()

def fakedata(rows: int):
    file = 'server/cypher/clients.csv'
    with open(file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile, delimiter=',',
                                quotechar='"', quoting=csv.QUOTE_NONNUMERIC)
        for i in range(1, rows + 1):
            writer.writerow([fake.unique.name(), fake.credit_card_number(), 
                             fake.credit_card_security_code(), fake.credit_card_expire()])

fakedata(30)