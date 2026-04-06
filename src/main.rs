use serde::{Deserialize,Serialize};
use std::{collections::HashMap,env,error::Error,fs,io,process::ExitCode};
#[derive(Serialize,Deserialize)]
struct Entry{username:String,password:String}
type Db=HashMap<String,Entry>;
fn main()->ExitCode{match run(){Ok(())=>ExitCode::SUCCESS,Err(e)=>{eprintln!("{e}");ExitCode::FAILURE}}}
fn run()->Result<(),Box<dyn Error>>{
    match env::args().collect::<Vec<_>>().as_slice(){
        [_,cmd,site,user,pass] if cmd=="add"=>{
            let mut db=load()?;
            db.insert(site.clone(),Entry{username:user.clone(),password:pass.clone()});
            save(&db)
        }
        [_,cmd,site] if cmd=="get"=>{
            let db=load()?;
            let e=db.get(site).ok_or_else(||io::Error::other(format!("site not found: {site}")))?;
            println!("username: {}\npassword: {}",e.username,e.password);
            Ok(())
        }
        [_,cmd] if cmd=="list"=>{
            let db=load()?;
            let mut sites:Vec<_>=db.keys().map(String::as_str).collect();
            sites.sort_unstable();
            for site in sites{println!("{site}")}
            Ok(())
        }
        _=>Err(io::Error::new(io::ErrorKind::InvalidInput,"usage: add <site> <username> <password> | get <site> | list").into())
    }
}
fn load()->Result<Db,Box<dyn Error>>{
    match fs::read_to_string("db.json"){
        Ok(s)=>Ok(if s.trim().is_empty(){HashMap::new()}else{serde_json::from_str(&s)?}),
        Err(e) if e.kind()==io::ErrorKind::NotFound=>{fs::write("db.json",b"{}")?;Ok(HashMap::new())}
        Err(e)=>Err(e.into())
    }
}
fn save(db:&Db)->Result<(),Box<dyn Error>>{fs::write("db.json",serde_json::to_vec(db)?)?;Ok(())}
