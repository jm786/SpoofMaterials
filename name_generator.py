import names, time, threading
from faker import Faker
from tqdm import tqdm
start_time = time.time()
fake = Faker()
def main():
    chunk = ""

    def name_grab():
        chunck = chunk.join(fake.last_name()+"\n")

    threads = []
    for x in tqdm(range(2000000)):
        t = threading.Thread(target = name_grab)
        #threads.append(t)
        t.start()
   
    f = open("names_file.txt", 'r+')
    f.write(chunk)
    f.close() 
    '''
    with open("names_file.txt", 'w') as f:
        for x in tqdm(range(2000000)):
            f.write(fake.last_name() + "\n")
    '''
    
main()

print("--- %s seconds ---" % (time.time() - start_time))
