#include <eosio.xec/eosio.xec.hpp>


namespace eosio {

    void eosioxec::setperm2(name acc, const std::vector<uint8_t>& perms ){

		require_auth( _self );
		
		require_recipient( acc );
		check( is_account( acc ), "Account does not exist.");
		

		permissions perm( _self, _self.value );
		auto existing = perm.find( acc.value );
		
		if ( existing != perm.end() ) {
			
			perm.modify( existing, _self, [&]( auto& p ){
				p.createacc = perms[0];
				p.vote = perms[1]; 
				p.regprod = perms[2]; 
				p.regproxy = perms[3]; 
				p.setcontract = perms[4]; 
				p.namebids = perms[5]; 
				p.rex = perms[6]; 

			});
		} else {
			perm.emplace( _self, [&]( auto& p ){
				
				p.acc = acc;
				
				p.createacc = perms[0];
				p.vote = perms[1]; 
				p.regprod = perms[2]; 
				p.regproxy = perms[3]; 
				p.setcontract = perms[4]; 
				p.namebids = perms[5]; 
				p.rex = perms[6]; 


			});
		}
    }
	

    void eosioxec::setperm(name acc, const std::map<std::string,uint8_t>& perms ){
		require_auth( _self );
		
		require_recipient( acc );
		check( is_account( acc ), "Account does not exist.");
		

		permissions perm( _self, _self.value );
		auto existing = perm.find( acc.value );
		
		if ( existing != perm.end() ) {
			perm.modify( existing, _self, [&]( auto& p ){
				for (auto it=perms.begin(); it!=perms.end(); ++it){
					if(it->first == "createacc") { p.createacc = it->second; }
					if(it->first == "vote") { p.vote = it->second; }
					if(it->first == "regprod") { p.regprod = it->second; }
					if(it->first == "regproxy") { p.regproxy = it->second; }
					if(it->first == "setcontract") { p.setcontract = it->second; }
					if(it->first == "namebids") { p.namebids = it->second; }
					if(it->first == "rex") { p.rex = it->second; }
				}			
			});
		} else {
			perm.emplace( _self, [&]( auto& p ){
				
				p.acc = acc;
				
				p.createacc = 0;
				p.vote = 0;
				p.regprod = 0;
				p.regproxy = 0;
				p.setcontract = 0;
				p.namebids = 0;
				p.rex = 0;
				for (auto it=perms.begin(); it!=perms.end(); ++it){
					if(it->first == "createacc") { p.createacc = it->second; }
					if(it->first == "vote") { p.vote = it->second; }
					if(it->first == "regprod") { p.regprod = it->second; }
					if(it->first == "regproxy") { p.regproxy = it->second; }
					if(it->first == "setcontract") { p.setcontract = it->second; }
					if(it->first == "namebids") { p.namebids = it->second; }
					if(it->first == "rex") { p.rex = it->second; }
				}			

				//p.createacc = perms.find("createacc")->second ? perms.find("createacc")->second : 0;
				//p.vote = perms.find("vote")->second ? perms.find("vote")->second : 0;
				//p.regprod = perms.find("regprod")->second ? perms.find("regprod")->second : 0;
				//p.regproxy = perms.find("regproxy")->second ? perms.find("regproxy")->second : 0;
				//p.setcontract = perms.find("setcontract")->second ? perms.find("setcontract")->second : 0;
				//p.namebids = perms.find("namebids")->second ? perms.find("namebids")->second : 0;
				//p.rex = perms.find("rex")->second ? perms.find("rex")->second : 0;
			});
		}
    }
	


	void eosioxec::setuserinfo(name acc, std::string data ){

		
		internal_use_do_not_use::require_auth2("welcome.xec"_n.value, "newacc"_n.value );
		require_recipient( acc );
		check( is_account( acc ), "Account does not exist.");
		

		usersinfo usrinf( _self, _self.value );
		auto existing = usrinf.find( acc.value );
		
		if ( existing != usrinf.end() ) {
			usrinf.modify( existing, _self, [&]( auto& p ){
				p.data = data;
			});
		} else {
			usrinf.emplace( _self, [&]( auto& p ){
				p.acc = acc;
				p.data = data;
			});
		}

	}
	
	void eosioxec::reqperm(name acc, std::string permission ){

		require_auth( acc );
		
		permissions perm( _self, _self.value );
		auto existing = perm.find( acc.value );
		
		if ( existing != perm.end() ) {
			perm.modify( existing, _self, [&]( auto& p ){
				if(permission == "createacc" && (existing->createacc != 4 || existing->createacc != 1) ) { p.createacc = 2; }
				if(permission == "vote" && (existing->vote != 4 || existing->vote != 1) ) { p.vote = 2; }
				if(permission == "regprod" && (existing->regprod != 4 || existing->regprod != 1) ) { p.regprod = 2; }
				if(permission == "regproxy" && (existing->regproxy != 4 || existing->regproxy != 1) ) { p.regproxy = 2; }
				if(permission == "setcontract" && (existing->setcontract != 4 || existing->setcontract != 1) ) { p.setcontract = 2; }
				if(permission == "namebids" && (existing->namebids != 4 || existing->namebids != 1) ) { p.namebids = 2; }
				if(permission == "rex" && (existing->rex != 4 || existing->rex != 1) ) { p.rex = 2; }
			});
		} else {
			perm.emplace( _self, [&]( auto& p ){
				p.acc = acc;
				
				p.createacc = 0;
				p.vote = 0;
				p.regprod = 0;
				p.regproxy = 0;
				p.setcontract = 0;
				p.namebids = 0;
				p.rex = 0;
				
				if(permission == "createacc") { p.createacc = 2; }
				if(permission == "vote") { p.vote = 2; }
				if(permission == "regprod") { p.regprod = 2; }
				if(permission == "regproxy") { p.regproxy = 2; }
				if(permission == "setcontract") { p.setcontract = 2; }
				if(permission == "namebids") { p.namebids = 2; }
				if(permission == "rex") { p.rex = 2; }			
			});
		}
    }
	
	
    void eosioxec::remove(name acc){

		require_auth( _self );
		
		require_recipient( acc );
		
		permissions perm( _self, _self.value );
		auto existing = perm.find( acc.value );
		
		check ( existing != perm.end(), "Account not found." );
			
		perm.erase( existing );	
	
    }


} /// namespace eosio


EOSIO_DISPATCH( eosio::eosioxec, (setperm)(setperm2)(remove)(reqperm)(setuserinfo) )