#include <iostream>
#include <stdlib.h>
#include <stdint.h>
#include <iostream>
#include <math.h>
#include "bignum.h"
#include <time.h>
#include <sstream>
#include <iomanip>
#include "ripemd.c"

using namespace std;

std::string uint8_to_hex_string(const uint8_t *v, const size_t s) {
  std::stringstream ss;

  ss << std::hex << std::setfill('0');

  for (int i = 0; i < s; i++) {
    ss << std::hex << std::setw(2) << static_cast<int>(v[i]);
  }

  return ss.str();
}

BigNum m,p,q,g,One,r,s,y;

void sign(BigNum x)
{
    BigNum k,h_m;
    string h_m_str,k_str,r_str_m,s_str_m;
    size_t msglen = 100;
    uint8_t msg[msglen];
    size_t hashlen = 20;
    uint8_t hash[hashlen];

    cout <<"\nEnter message : ";
    cin>>h_m_str;
    h_m = StringToArray(h_m_str);

    memcpy(msg, h_m_str.c_str(), sizeof(msg));
    ripemd(msg, msglen, hash);
    std::string hash_message = uint8_to_hex_string(hash, hashlen);
    std::cout<<"\nHash output :" << hash_message << std::endl;

    do{
        k = PwrMod(StringToArray(to_string(rand())),One,Sub(q,One));
        k_str = value_number(k);
    }while(k_str.compare("")==0);

    r = PwrMod(PwrMod(g,k,p),One,q);
    s = PwrMod(Mul(Inverse(k,q),Add(StringToArray(hash_message),Mul(x,r))),One,q);

    r_str_m = value_number(r);
    s_str_m = value_number(s);

    if(r_str_m.compare("")==0)
		r_str_m = "0";
    if(s_str_m.compare("")==0)
		s_str_m = "0";

    cout<<"\n\nDigital signature is :";
    cout<<"\n\tr="<<r_str_m;
    cout<<"\n\ts="<<s_str_m;
}

void verify(BigNum r,BigNum s)
{
    BigNum w,h_v,u1,u2,v,r_v,s_v;
    string h_v_str,r_v_str,s_v_str;

    size_t msglen = 100;
    uint8_t msg[msglen];
    size_t hashlen = 20;
    uint8_t hash[hashlen];

    cout <<"\nEnter message : ";
    cin>>h_v_str;
    cout <<"\nEnter r : ";
    cin>>r_v_str;
    cout <<"\nEnter s : ";
    cin>>s_v_str;

    h_v = StringToArray(h_v_str);
    r_v = StringToArray(r_v_str);
    s_v = StringToArray(s_v_str);

    memcpy(msg, h_v_str.c_str(), sizeof(msg));
    ripemd(msg, msglen, hash);
    std::string hash_verify = uint8_to_hex_string(hash, hashlen);
    std::cout<<"\nHash output :" << hash_verify << std::endl;

    w = Inverse(s_v,q);
    u1 = PwrMod(Mul(StringToArray(hash_verify),w),One,q);
    u2 = PwrMod(Mul(r_v,w),One,q);
    v = PwrMod((PwrMod(Mul(PwrMod(g,u1,p),PwrMod(y,u2,p)),One,p)),One,q);

    string v_str;
    v_str = value_number(v);

    if(v_str.compare(r_v_str)==0)
        cout<<"\n Verified";
    else
        cout<<"\n Rejected";
}

int main()
{
    BigNum h,x;
    string h_str,g_str,y_str,x_str;
	One.Num[0] = 1;
	srand (time(NULL));

    p = StringToArray("8490596416367848650087159567646773591615403553294465336662715867127232816933488346501617931682626979");
    q = StringToArray("4245298208183924325043579783823386795807701776647232668331357933563616408466744173250808965841313489");

    cout<<"\nImplementation of DSS\n";

    DivResult DR;
    DR = DivLarge(Sub(p,One),q);

    do{
        h = PwrMod(StringToArray(to_string(rand())),One,Sub(p,StringToArray("2")));
        h_str = value_number(h);

    }while(h_str.compare("1")==0 || h_str.compare("")==0);

    g = PwrMod(h,DR.Result,p);
    g_str = value_number(g);

    do{
        x = PwrMod(StringToArray(to_string(rand())),One,Sub(q,One));
        x_str = value_number(x);
    }while(x_str.compare("")==0);

    y = PwrMod(g,x,p);
    y_str = value_number(y);


    if(g_str.compare("")==0)
		g_str = "0";
	if(y_str.compare("")==0)
		y_str = "0";

    cout<<"\nPublic key :";
    cout<<"\n\tp="<<value_number(p);
    cout<<"\n\tq="<<value_number(q);
    cout<<"\n\tg="<<g_str;
    cout<<"\n\ty="<<y_str;

    cout<<"\n\nPrivate key :";
    cout<<"\n\tx="<<x_str;

    int choice;
    while(1){
    cout<<"\n\nEnter your choice:\t1)Sign\t2)Verify\t3)Exit\n";
    cin>>choice;
    switch(choice) {
      case 1: {
          sign(x);
          break;
        }
      case 2: {
        verify(r,s);
        break;
      }
      case 3: {
          break;
        }
      default: {
          cout<<("\nInvalid choice,Enter valid choice.\n");
        }
    }
    if(choice==3)
      break;
    }
    return 0;
}
