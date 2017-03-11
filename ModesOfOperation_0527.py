# program template as part of information security 2 Assignment 3 template.
# Program can be modified to suit needs of the assignment.
# This template is just a guide line to help simplify implementing the assignment.
# Program logic designed by Prof. David Levine[UTA].
# Program template written by Jerrin Jacob.

#Poonam Deepak Sathe
#Student ID: 1001230527


import sys
import datetime

class ModesOfOperation0527:
    def __init__(self):
        # s-box initializing parameters
        # s-box 1
        # 101 010 001 110 011 100 111 000
        # 001 100 110 010 000 111 101 011
        # s-box 2
        # 100 000 110 101 111 001 011 010
        # 101 011 000 111 110 010 001 100
        print ("Initializing the program variables")
        # variable to store name
        self.name = ""
        # variable to store uta id
        self.uta_id = ""
        # variable to store s-box 1
        self.s1_0 = ['101', '010', '001', '110', '011', '100', '111', '000']
        self.s1_1 = ['001', '100', '110', '010', '000', '111', '101', '011']
        # similar logic for s2
        self.s2_0 = ['100', '000', '110', '101', '111', '001', '011', '010']
        self.s2_1 = ['101', '011', '000', '111', '110', '010', '001', '100']

        self.key=""
        self.round2Encrypt=""
        self.round2Decrypt=""
        self.L1=""
        self.R1=""
        self.outputString=""

    # to get input from the user
    def get_input(self):
        # getting the name
        self.name = raw_input("Enter your name and it should be exactly 10 character long")
        # length check of 10
        if len(self.name) != 10:
            print("First name isn't 10 character long")
            while len(self.name)!=10:
                self.name+="x"
            print "Name after converting to 10 characters: "+self.name

        if len(self.name)>10:
            sys.exit()

        # getting the uta id
        self.uta_id = raw_input("Enter your UTA ID and it should be 10 digits long")
        # length check of 10
        if len(self.uta_id) != 10:
            print("UTA ID should be 10 digits long")
            # exit
            sys.exit()
            # key
        self.dob = raw_input("Enter date of birth in format yyyy.mm.dd")
        juline_d=modes.get_julian_date(self.dob)
        self.key=format(juline_d, '09b')
        print "9 bit key value is: "+self.key

        # plain text formation
        self.plain_text = self.name.upper() + " " + self.uta_id + "."
        print "Plain Text is : "+self.plain_text

        # keys
        k1 = self.key[:8]
        print "K1: "+k1
        k2 = self.key[-8:]
        print "K2: "+k2

        # taking plain text input blockwise - two blocks
        for i in range(0,len(self.plain_text),2):
            block=self.plain_text[i:i+2]
            # checking charachter in block
            for ch in block:
                if ch.isdigit() or ch.isspace() or ch==".":
                    L0R0=modes.encode_map_numbers(block)
                else:
                    L0R0=modes.encode_map_string(block)

            # round 1 encryption
            self.L1,self.R1=modes.mini_des_encrypt(L0R0,k1)

            # input for round 2
            self.L1R1=self.L1+self.R1

            # encryption round 2
            self.L2,self.R2=modes.mini_des_encrypt(self.L1R1,k2)
            self.round2Encrypt+=self.R2+self.L2
        print "Encrypted output after two Rounds: "+self.round2Encrypt

        # decryption of the text
        for j in range(0, len(self.round2Encrypt), 12):
            block_2 = self.round2Encrypt[j:j + 12]
            #passing block for round 1 decryption
            self.Dec_L1, self.Dec_R1 = modes.mini_des_encrypt(block_2, k2)
            self.Dec_L1R1 = self.Dec_L1 + self.Dec_R1
            # decryption round2
            self.Dec_L2, self.Dec_R2 = modes.mini_des_encrypt(self.Dec_L1R1, k1)
            self.round2Decrypt += self.Dec_R2 + self.Dec_L2
        print "Result of decryption round 2: "+self.round2Decrypt

        # converting back to plaintext
        for j in range(0, len(self.round2Decrypt), 6):
            ascii_val = int(self.round2Decrypt[j:j + 6], 2)
            # print "Decoded value"+chr(number+ord('a')-1)

            if ascii_val == 38:
                # print " "
                self.outputString += " "

            elif ascii_val == 39:
                # print "."
                self.outputString += "."

            elif (ascii_val <= 26):
                # print ""+chr(number+ord('0')-27)
                self.outputString += chr(ascii_val + ord('A') - 1)

            elif (ascii_val >= 27):
                self.outputString += chr(ascii_val + ord('0') - 27)

        print "Message decrypted back to input text :" + self.outputString


    # to encode string to decimal to binary
    def encode_map_string(self, input_string):
        # get the length of the input string
        length = len(input_string)
        binary = ""
        # looping through the length of string
        for i in range(0, length):
            binary += format((ord(input_string[i]) - ord('A') + 1), '06b')

        return binary

    # to encode numbers to decimal to binary
    def encode_map_numbers(self, input_numbers):
        # get the length of input numbers
        length = len(input_numbers)
        binary = ""
        for i in range(0, length):
            if ' ' in input_numbers[i]:
                binary+=format(38,'06b')
            elif "." in input_numbers[i]:
                binary+=format(39,'06b')
            else:
                binary += format((ord(input_numbers[i]) - ord('0'))+27, '06b')
        return binary

    def mini_des_encrypt(self, input,inputkey):
        # left and right selection
        left = input[:6]
        right = input[6:]

        # expansion step
        l1 = list(right)
        exp = []
        exp.append(l1[0])
        exp.append(l1[1])
        exp.append(l1[3])
        exp.append(l1[2])
        exp.append(l1[3])
        exp.append(l1[2])
        exp.append(l1[4])
        exp.append(l1[5])

        self.expanded = ''.join(exp)

    # xor step with key
        self.f_rvalue = self.XOR_number(inputkey, self.expanded)

    # sbox application step
    #giving first half as input to s1 box
        self.s1result=self.S1box(int(self.f_rvalue[:4],2))

        #giving second half as input to s2 box
        self.s2result=self.S2box(int(self.f_rvalue[-4:],2))

    # sbox output xor step with left
        self.sbox_result=self.s1result+self.s2result
        self.left_xor_sbox=self.XOR_number(self.sbox_result,left)

    # return encrypted text
        return right,self.left_xor_sbox


    def S1box(self,sboxVal):
        return {

            0:'101',
            1:'010',
            2:'001',
            3:'110',
            4:'011',
            5:'100',
            6:'111',
            7:'000',
            8:'001',
            9:'100',
            10:'110',
            11:'010',
            12:'000',
            13:'111',
            14:'101',
            15:'011'
        }.get(sboxVal)

    def S2box(self,sboxVal):
        return{
            0: '100',
            1: '000',
            2: '110',
            3: '101',
            4: '111',
            5: '001',
            6: '011',
            7: '010',
            8: '001',
            9: '011',
            10: '000',
            11: '111',
            12: '110',
            13: '010',
            14: '001',
            15: '100'
        }.get(sboxVal)

    def XOR_number(self, input1, input2):
        y = int(input1, 2) ^ int(input2, 2)
        if len(input1)== 8:
            return format(y,'08b')
        else:
            return format(y, '06b')

    def get_julian_date(self, date):
        # date in year.month.day eg: 2017.03.02
        date_format = '%Y.%m.%d'
        # converting it to date format of python
        date_input = datetime.datetime.strptime(date, date_format)
        # converting it to time tuple
        time_tuple = date_input.timetuple()
        # returning the julian date
        return time_tuple.tm_yday


if __name__ == "__main__":
    # creating instance of ModesOfOperation Class
    modes = ModesOfOperation0527()
    modes.get_input()