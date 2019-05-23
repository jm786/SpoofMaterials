import names, time
from faker import Faker
from tqdm import tqdm
fake = Faker()
start_time = time.time()

def main():
    with open("names_file.txt", 'w') as f:
        for x in tqdm(range(2000000)):
            f.write(fake.last_name() + "\n")

main()

print("--- %s seconds ---" % (time.time() - start_time))
