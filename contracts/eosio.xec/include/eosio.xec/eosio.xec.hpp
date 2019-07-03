#pragma once

#include <eosio/eosio.hpp>

namespace eosiosystem {
   class system_contract;
}

namespace eosio {

	class [[eosio::contract("eosio.xec")]] eosioxec : public contract {
		public:
			using contract::contract;

			[[eosio::action]]
			void setperm(name acc, const std::map<std::string,uint8_t>& perms);
			using setperm_action = eosio::action_wrapper<"setperm"_n, &eosioxec::setperm>;

			[[eosio::action]]
			void setperm2(name acc, const std::vector<uint8_t>& perms);
			using setperm2_action = eosio::action_wrapper<"setperm2"_n, &eosioxec::setperm2>;

			[[eosio::action]]
			void remove(name acc);
			using remove_action = eosio::action_wrapper<"remove"_n, &eosioxec::remove>;

			[[eosio::action]]
			void reqperm(name acc, std::string permission );
			using reqperm_action = eosio::action_wrapper<"reqperm"_n, &eosioxec::reqperm>;
			
			[[eosio::action]]
			void setuserinfo(name acc, std::string data );
			using setuserinfo_action = eosio::action_wrapper<"setuserinfo"_n, &eosioxec::setuserinfo>;


			static std::map<std::string,uint8_t> get_priv( name contract_account, name acc ){
				std::map<std::string,uint8_t> res;
				
				//exception for eosio account
				if ( acc == "eosio"_n ) {
					res["createacc"] = 1; res["vote"] = 1; res["regprod"] = 1; res["regproxy"] = 1; res["setcontract"] = 1; res["namebids"] = 1; res["rex"] = 1;
					return res;			
				}
				
				res["createacc"] = 0; res["vote"] = 0; res["regprod"] = 0; res["regproxy"] = 0; res["setcontract"] = 0; res["namebids"] = 0; res["rex"] = 0;

				permissions perm( contract_account, contract_account.value );
				auto existing = perm.find( acc.value );
				if ( existing != perm.end() ) {
					res["createacc"] = existing->createacc;
					res["vote"] = existing->vote;
					res["regprod"] = existing->regprod;
					res["regproxy"] = existing->regproxy;

					res["setcontract"] = existing->setcontract;
					res["namebids"] = existing->namebids;
					res["rex"] = existing->rex;
				}
				return res;			
			}

			/*
			static std::map<int,bool> get_priv( name contract_account, name acc ){

			std::map<int,bool> res;
			res[0] = 0; res[1] = 0; res[2] = 0; res[3] = 0;

			permissions perm( contract_account, contract_account.value );
			auto existing = perm.find( acc.value );
			if ( existing != perm.end() ) {
			res[0] = existing->createacc;
			res[1] = existing->vote;
			res[2] = existing->regprod;
			res[3] = existing->regproxy;

			}
			return res;			
			}
			*/


	private:

		// 0 = none, 1 = on, 2 = pending, 3 = off, 4 = banned
		struct [[eosio::table]] permission {
			name		acc;
			uint8_t		createacc;
			uint8_t		vote;
			uint8_t		regprod;
			uint8_t		regproxy;
			uint8_t		setcontract;
			uint8_t		namebids;
			uint8_t		rex;

			uint64_t primary_key()const { return acc.value; }
		};

		typedef eosio::multi_index< "permissions"_n, permission > permissions;


		struct [[eosio::table]] userinfo {
			name			acc;
			std::string		data;

			uint64_t primary_key()const { return acc.value; }
		};

		typedef eosio::multi_index< "usersinfo"_n, userinfo > usersinfo;
		
		//add singelton for producer pay config

	};

} /// namespace eosio
