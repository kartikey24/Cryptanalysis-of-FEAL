// Differential cryptanalysis of FEAL-4 using Chosen Plaintext Attack

#include <iostream>
using namespace std;

#define MAX_CHOSEN_PAIRS 10000

typedef unsigned long long ull;
typedef unsigned uint;
typedef unsigned char byt;

int num_plaintexts;
uint key[6];

ull plaintext0[MAX_CHOSEN_PAIRS];
ull ciphertext0[MAX_CHOSEN_PAIRS];
ull plaintext1[MAX_CHOSEN_PAIRS];
ull ciphertext1[MAX_CHOSEN_PAIRS];

inline uint getLeftHalf(ull x)
{
	return x >> 32;
}

inline uint getRightHalf(ull x)
{
	return x & 0xFFFFFFFFULL;
}

inline ull getCombinedHalves(uint a, uint b){
	return (ull(a)<<32) | (ull(b) & 0xFFFFFFFFULL);
}

void createRandomKeys()
{
    srand(time(NULL));

    for(int i = 0; i < 6; i++)
        key[i] = (rand() << 16) | (rand() & 0xFFFFU);
}

byt g(byt a, byt b, byt x){
	byt tmp = a + b + x;
	return ( tmp << 2 ) | ( tmp >> 6 );
}

uint f(uint input){

	byt x[4], y[4];
	for(int i=0; i<4; i++)
	{
		x[3-i] = byt(input & 0xFF);
		input >>= 8;
	}

	y[1] = g(x[0]^x[1], x[2]^x[3], 1);
	y[0] = g(x[0], y[1], 0);
	y[2] = g(x[2]^x[3], y[1], 0);
	y[3] = g(x[3], y[2], 1);

	uint output=0;
	for(int i=0; i<4; i++)
		output += (uint(y[i])<<(8*(3-i)));

	return output;
}

ull encrypt(ull plaintext){
	uint initialLeft = getLeftHalf(plaintext) ^ key[4];
	uint initialRight = getRightHalf(plaintext) ^ key[5];

	uint round1Left = initialLeft ^ initialRight;
	uint round1Right = initialLeft ^ f(round1Left ^ key[0]);

	uint round2Left = round1Right;
    uint round2Right = round1Left ^ f(round1Right ^ key[1]);

    uint round3Left = round2Right;
    uint round3Right = round2Left ^ f(round2Right ^ key[2]);

    uint round4Left = round3Left ^ f(round3Right ^ key[3]);
    uint round4Right = round4Left ^ round3Right;

    return getCombinedHalves(round4Left, round4Right);
}

void generatePlaintextCiphertextPairs(ull inputDiff)
{
	cout<<"Generating "<<num_plaintexts<<" plaintext-ciphertext pairs\n";
	cout<<"Using input differential 0x"<<hex<<inputDiff<<dec<<"\n";

	srand(time(NULL));

	for(int i=0; i<num_plaintexts; i++){
		plaintext0[i] = (rand() & 0xFFFFULL) << 48;
		plaintext0[i] += (rand() & 0xFFFFULL) << 32;
        plaintext0[i] += (rand() & 0xFFFFULL) << 16;
        plaintext0[i] += (rand() & 0xFFFFULL);

        ciphertext0[i] = encrypt(plaintext0[i]);
        plaintext1[i] = plaintext0[i] ^ inputDiff;
        ciphertext1[i] = encrypt(plaintext1[i]);

        // cout<<plaintext0[i]<<" "<<plaintext1[i]<<"    "<<ciphertext0[i]<<" "<<ciphertext1[i]<<endl;
	}
}

void decryptLastOperation()
{
        for(int i = 0; i < num_plaintexts; i++)
        {
            uint cipherLeft0 = getLeftHalf(ciphertext0[i]);
            uint cipherRight0 = getRightHalf(ciphertext0[i]) ^ cipherLeft0;
            uint cipherLeft1 = getLeftHalf(ciphertext1[i]);
            uint cipherRight1 = getRightHalf(ciphertext1[i]) ^ cipherLeft1; 
			
			ciphertext0[i] = getCombinedHalves(cipherLeft0, cipherRight0);   
			ciphertext1[i] = getCombinedHalves(cipherLeft1, cipherRight1);
         }   
}

uint crackHighestRound(uint differential)
{
    cout<<"  Using output differential of 0x"<< hex<<differential<<dec<<"\n";
    cout<<"  Cracking...\n";
    // cout<<num_plaintexts<<endl;
    
    for(uint tmpKey = 0x00000000U; tmpKey <= 0xFFFFFFFFU; tmpKey++)
    {
    	// cout<<tmpKey<<endl;
        int score = 0;

        for(int i = 0; i < num_plaintexts; i++)
        {
            

            uint cipherRight0 = getRightHalf(ciphertext0[i]);
            uint cipherLeft0 = getLeftHalf(ciphertext0[i]);
            uint cipherRight1 = getRightHalf(ciphertext1[i]);
            uint cipherLeft1 = getLeftHalf(ciphertext1[i]);

            uint cipherLeft = cipherLeft0 ^ cipherLeft1;
            uint fOutDiffActual = cipherLeft ^ differential;

            uint fInput0 = cipherRight0 ^ tmpKey;
            uint fInput1 = cipherRight1 ^ tmpKey;
            uint fOut0 = f(fInput0);
            uint fOut1 = f(fInput1);
            uint fOutDiffComputed = fOut0 ^ fOut1;

            if (fOutDiffActual == fOutDiffComputed) score++; 
            else break;
        }

        if (score == num_plaintexts)
        {
            cout<<"found key : 0x"<<hex<<tmpKey<<dec<<"\n";
            cout<<flush;
            return tmpKey;
        }
    }
    
    cout<<"failed\n";
    return 0;
}


void decryptHighestRound(uint crackedKey)
{
 	 for(int i = 0;  i< num_plaintexts; i++)
 	 {
 	        uint cipherLeft0 = getRightHalf(ciphertext0[i]);
 	        uint cipherLeft1 = getRightHalf(ciphertext1[i]);
			
			uint cipherRight0 = f(cipherLeft0 ^ crackedKey) ^ getLeftHalf(ciphertext0[i]);
			uint cipherRight1 = f(cipherLeft1 ^ crackedKey) ^ getLeftHalf(ciphertext1[i]);
			
			ciphertext0[i] = getCombinedHalves(cipherLeft0, cipherRight0);
			ciphertext1[i] = getCombinedHalves(cipherLeft1, cipherRight1);	   
   	 }
}

int main(int argc, char **argv){

	cout<<"Differential Cryptanalysis of FEAL-4\n\n\n";

	if(argc==1) num_plaintexts = 12;
	else if(argc==2) num_plaintexts = atoi(argv[1]);
	else{
		cout<<"Usage: "<<argv[0]<<" [Number of chosen plaintexts]\n";
		return 0;
	}

	createRandomKeys();
	uint startTime = time(NULL);

	//Round 4

	cout<<"Round 4: To find K3\n\n";
	generatePlaintextCiphertextPairs(0x8080000080800000ULL);
	decryptLastOperation();

	uint roundStartTime = time(NULL);
	uint crackedKey3 = crackHighestRound(0x02000000U);
	uint roundEndTime = time(NULL);
	cout<< "  Time to crack round #4 = "<< int(roundEndTime - roundStartTime)<<" seconds\n\n" ;


	//Round 3
	cout<<"Round 3: To find K2\n";
	generatePlaintextCiphertextPairs(0x0000000080800000ULL);
	decryptLastOperation();
	decryptHighestRound(crackedKey3);

	roundStartTime = time(NULL);
	uint crackedKey2 = crackHighestRound(0x02000000U);
	roundEndTime = time(NULL);
	cout<< "  Time to crack round #3 = "<< int(roundEndTime - roundStartTime)<<" seconds\n\n" ;

	//Round 2

	cout<<"Round 2: To find K1\n";
	generatePlaintextCiphertextPairs(0x0000000002000000ULL);
	decryptLastOperation();
	decryptHighestRound(crackedKey3);
	decryptHighestRound(crackedKey2);

	roundStartTime = time(NULL);
	uint crackedKey1 = crackHighestRound(0x02000000U);
	roundEndTime = time(NULL);
	cout<< "  Time to crack round #2 = "<< int(roundEndTime - roundStartTime)<<" seconds\n\n" ;


	//Round 1
	cout<<"Round 1: To find K0\n";
	decryptHighestRound(crackedKey1);
	cout<<"Cracking ... \n";

	roundStartTime = time(NULL);
/*
	uint crackedKey0 = crackHighestRound(0x80800000U);
	roundEndTime = time(NULL);
	cout<< "  Time to crack round #1 = "<< int(roundEndTime - roundStartTime)<<"seconds\n\n" ;


	uint plainLeft0 = getLeftHalf(plaintext0[0]);
    uint plainRight0 = getRightHalf(plaintext0[0]);
    uint cipherLeft0 = getLeftHalf(ciphertext0[0]);
    uint cipherRight0 = getRightHalf(ciphertext0[0]);
    
    uint temp = f(cipherRight0 ^ crackedKey0) ^ cipherLeft0;
    uint crackedKey4 = temp ^ plainLeft0;
    uint crackedKey5 = temp ^ cipherRight0 ^ plainRight0;

    cout<<"found keys : "<<hex<<crackedKey4<<"  "<<crackedKey5<<dec<<"\n";*/

	uint crackedKey0 = 0;
	uint crackedKey4 = 0;
	uint crackedKey5 = 0;

    for(uint tmpK0 = 0; tmpK0 < 0xFFFFFFFFL; tmpK0++)
    {
	      uint tmpK4 = 0;
	      uint tmpK5 = 0;

 		  for(int i= 0; i < num_plaintexts; i++)
 		  {
		   		uint plainLeft0 = getLeftHalf(plaintext0[i]);
		   		uint plainRight0 = getRightHalf(plaintext0[i]);
		   		uint cipherLeft0 = getLeftHalf(ciphertext0[i]);
		   		uint cipherRight0 = getRightHalf(ciphertext0[i]);
		   		
	 	   		uint temp = f(cipherRight0 ^ tmpK0) ^ cipherLeft0;
	 	  		if (tmpK4 == 0)
	 	  		{
				   tmpK4 = temp ^ plainLeft0;
  		           tmpK5 = temp ^ cipherRight0 ^ plainRight0;
			    }
			  	else if (((temp ^ plainLeft0) != tmpK4) || ((temp ^ cipherRight0 ^ plainRight0) != tmpK5))
  		        {
				 	 tmpK4 = 0;
				 	 tmpK5 = 0;
					  break; 	 
 		 		}
           }
 	  	   if (tmpK4 != 0)
  		   {

		   	  crackedKey0 = tmpK0;
		   	  crackedKey4 = tmpK4;
		   	  crackedKey5 = tmpK5;
				 		   	  
		   	  break;
	       
		   }	  
    }

    uint endTime = time(NULL);
    cout<<"Total time taken = "<<int(endTime-startTime)<<" seconds\n";


    cout<<"\n\n\n";

    generatePlaintextCiphertextPairs(0x123FEC3C243BA9B2LL);

    key[0]= crackedKey0;
    key[1]= crackedKey1;
    key[2]= crackedKey2;
    key[3]= crackedKey3;
    key[4]= crackedKey4;
    key[5]= crackedKey5;
    
 

    for(int i=0; i<num_plaintexts; i++){
        ull a,b;
        a=encrypt(plaintext0[i]);
        b=encrypt(plaintext1[i]);
        if(a!=ciphertext0[i] || b!=ciphertext1[i]){
            cout<<"Failed "<<hex<<a<<" "<< b<<" "<< ciphertext0[i]<<" "<< ciphertext1[i]<<dec;
            return 0;
        }
    }
    cout<<"Each ciphertext created using Keys obtained above matches ciphertext generated by encryption algorithm\n";
    cout<<"Finished successfully\n";
    return 0;
}