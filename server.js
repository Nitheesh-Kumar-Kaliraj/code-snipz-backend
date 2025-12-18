const express = require('express');
const app = express();
const path = require("path");
const {open} = require("sqlite");
const sqlite3 = require("sqlite3");
const jwt = require("jsonwebtoken")
const bcrypt = require("bcrypt")
const cors = require("cors");
const { request } = require('http');
const dbPath = path.join(__dirname,'codesnippet.db');
app.use(express.json());
app.use(cors());

let db=null;

const initializeDBServer = async() =>{
    try{
        db = await open({
            filename: dbPath,
            driver: sqlite3.Database
        })
        app.listen(3000, ()=>{
            console.log("Server is running at http://localhost:3000/")
        })
    }catch (error){
        console.log(`DB Error: ${error}`)
        process.exit(1)
    }
}

initializeDBServer()    


const authenticateToken = (request, response, next) => {
  let jwtToken;
  const authHeader = request.headers["authorization"];
  if (authHeader !== undefined) {
    jwtToken = authHeader.split(" ")[1];
  }
  if (jwtToken === undefined) {
    response.status(401);
    response.send("Invalid JWT Token");
  } else {
    jwt.verify(jwtToken, "tokennum", async (error, payload) => {
      if (error) {
        response.status(401);
        response.send("Invalid JWT Token");
      } else {
        request.user_id = payload.user_id;
        next();
      }
    });
  }
};


app.post("/signup", async(request,response)=>{
    try{
        const {username,password, email} = request.body
        const checkuser = await db.get(`SELECT * FROM user WHERE user.username =? OR user.email = ?`, [username,email])
        if (username === "" && password==="" && email===""){
            response.status(400).json("Enter valid credentials!!!")
        }
        else if (username === null){
            response.status(400).json('Enter username!!')
        }else if (password.length<8){
            response.status(400).json("Password must be greater than 8 characters!!")
        }
        if (checkuser){
            response.status(400).json("Try different username and email")
        }
        if (password.length >= 8 && username.length>=1 && email.length >= 11){
            const hashedPassword = await bcrypt.hash(password,10)
            const addUser = `INSERT INTO user(username,password,email)
            VALUES (?,?,?)`;
            const signinResult = await db.run(addUser, [username,hashedPassword,email])
            response.json("User Added Successfully!!")
            console.log(signinResult.lastID)
        }
    }
    catch (error){
        console.error("Error Signin:", error.message)
        response.status(500).json({error: "Internal Server Error"})
    }
})

app.post("/auth/login", async(request,response)=>{
    try{
        const {username,password} = request.body 
        if (username === "" && password === ""){
            response.status(400).json({errorMsg:"Enter valid credentials!!"})
            console.error("Enter valid details!!")
        }else if (username.length === 0 && password >=8){
            response.status(400).json({errorMsg: "Enter valid username!!"})
            console.log("Wrong Password")
        }else if (username.length >= 1 && password <8){
            response.status(400).json({errorMsg: "Enter valid password"})
            console.log("Wrong password hhahahah")
        }
        const checkUser = await db.get(`SELECT * FROM user WHERE username=?`, username)
        console.log(checkUser)
        if (checkUser === undefined){
            response.status(400).json({errorMsg:"Invalid User!!"})
        }
        else{
            const checkPassword= await bcrypt.compare(password,checkUser.password)
            if (checkPassword){
                const payload = {user_id: checkUser.user_id}
                const jwtToken = jwt.sign(payload, "tokennum")
                response.status(201).json({jwtToken})
            }else{
                console.error("Wrong Password")
                response.status(400).json({errorMsg: "Enter valid password"})
            }
        }
    }
    catch(error){
        console.error("Login Error:", error)
        response.status(500).send({errorMsg:error.message})
    }
})

app.get("/users", async(request,response)=>{
    try{
        const getAllUsers = await db.all("SELECT * FROM user");
        response.json(getAllUsers)
    }
    catch(error) {
        console.error("Cannot fetch users", error.message)
        response.status(500).json({errorMsg: error.message})
    }
})

app.get("/user-details", authenticateToken, async(request,response)=>{
    try{
        const {user_id} = request
        const getUserDetails = `SELECT * FROM user WHERE user_id=?`
        if (getUserDetails){
            const userDetails = await db.get(getUserDetails, user_id)
            response.status(200).json(userDetails)
        }else{
            response.status(400).json("Invalid user!!")
        }
        
    }

    catch (error){
        console.error("Cannot fetch the user:", error)
        response.status(500).json({errorMsg:error.message})
    }
})

app.put("/user/change-password",authenticateToken, async(request,response)=>{
    try{
        const {username,newPassword} = request.body 
        const getUser = await db.get(`SELECT * FROM user WHERE username=?`, username)
        if (getUser === undefined){
            response.json("Invalid user!!!")
        }
        if (await bcrypt.compare(newPassword,getUser.password)){
            response.status(400).json("Cannot enter the previous password as new password")
        }else if (newPassword.length>=8){
            const hashedPassword = await bcrypt.hash(newPassword,10)
            const updateSnippet = `UPDATE user SET password=? WHERE username = ?`;
            await db.run(updateSnippet, [hashedPassword,username])
            response.status(200).json("User Details Updated!!!")
        }else{
            response.json("Password is too short")
        }
    }
    catch (error) {
        console.error("Password updation failed!!:", error.message)
        response.status(500).json({error: error.message})
    }
})

app.delete("/signout", authenticateToken, async(request,response)=>{
    try{
        const {user_id} = request
        const getUser = `DELETE FROM user WHERE user_id=?`;
        db.run(getUser,user_id)
        response.json("User Signed Out!!!")
    }
    catch(error){
        console.error("Error Signout:", error.message)
        response.status(500).json({error: "Internal Server Error"})
    }
})

app.get("/all-snippets", authenticateToken, async(request,response)=>{
    try{
        const getAllSnippets = `SELECT user.username AS by, snippets.tags , snippets.language, snippets.code, snippets.title FROM snippets JOIN user on snippets.user_id = user.user_id WHERE visibility='public'`
        if (getAllSnippets){
            const allSnippetsResult = await db.all(getAllSnippets)
            response.status(200).json(allSnippetsResult)
        }else{
            response.status(400).json("Cannot get the snippets!!")
        }
    }
    catch(error){
        console.error("Cannot retrieve all snippets", error)
        response.status(500).json({error:error.message})
    }
})


app.post("/add-snippet", authenticateToken, async(request,response)=>{
    try{
        const {title,code,language, tags} = request.body
        const {user_id} = request
        if (title && code &&language&& tags !== undefined){
            const addSnippet=`INSERT INTO snippets(user_id,title,code,language,tags,visibility,created_at)
            VALUES(?,?,?,?,?,'private',?)`
            const addNewSnippet = await db.run(addSnippet,[user_id,title,code,language,tags,new Date().toLocaleString("sv-SE", {timeZone: "Asia/Kolkata"})])
            response.status(200).json("Snippet added!!!")
            console.log(addNewSnippet)
        }else{
            response.status(400).json({errorMsg:"Enter all the required columns!!"})
        }
    }
    catch (error){
        console.error("Unable to post the snippet:", error.message)
        response.status(500).json({errorMsg: error.message})
    }
})

app.get("/my-snippets",authenticateToken, async(request,response)=>{
    try{
        const {user_id} = request
        const getAllSnippets = `SELECT * FROM snippets WHERE user_id=?`
        const snippetsList = await db.all(getAllSnippets, user_id)
        response.status(200).json(snippetsList)
    }
    catch (error){
        console.error("Cannot retrieve Snippets!!:", error.message)
        response.status(500).json({error: error.message})
    }
})

app.put("/update-snippet/:id", authenticateToken, async(request,response)=>{
    try{
        const {id} = request.params 
        const {user_id} = request
        const {title,code,language,tags} = request.body 
        const updateSnippet = `UPDATE snippets SET title=?, 
        code=?, language=?, tags=? WHERE snippet_id =? AND user_id=?`
        await db.run(updateSnippet, [title,code,language,tags,id,user_id])
        response.status(200).json("Snippet Updated!!")
    }
    catch(error){
        console.error("Update Snippet Error", error)
        response.status(500).json({error: error.message})
    }
})

app.get("/my-snippets/:id", authenticateToken, async(request,response)=>{
    try{
        const {id} = request.params 
        const {user_id} = request 
        const getSnippet = `SELECT * FROM snippets WHERE user_id=? AND snippet_id=?`
        const snippetDetail = await db.get(getSnippet, [user_id, id])
        console.log(snippetDetail)
        if (snippetDetail){
            response.status(200).json(snippetDetail)
        }
        else{
            response.status(400).json("Cannot access this snippet")
        }
    }
    catch (error){
        console.error("Cannot retrieve the snippet:", error)
        response.status(500).json({error: error.message})
    }
})

app.delete("/delete-snippet/:id", authenticateToken, async(request,response)=>{
    try{
        const {id} = request.params
        const {user_id} = request
        const checkOwnership = `SELECT * FROM snippets WHERE user_id =? AND snippet_id=?`
        const ownershipResult = await db.get(checkOwnership, [user_id,id])
        if (ownershipResult){
            const deleteSnippet = `DELETE FROM snippets WHERE snippet_id=? AND user_id=?`
            await db.run(deleteSnippet, [id, user_id])
            response.status(200).json("Snippet Deleted!!")
        }else{
            response.status(401).json("You are not allowed to delete this")
        }
    }
    catch(error){
        console.error("Cannot delete the snippet", error)
        response.status(500).json({error: error.message})
    }
})


app.put("/visibility/:id", authenticateToken, async(request,response)=>{
    try{
        const {id} = request.params
        const {user_id} = request 
        const checkVisibility = `SELECT * FROM snippets WHERE snippet_id=? AND user_id=?`
        const visibilityResult = await db.get(checkVisibility,[id,user_id])
        if(visibilityResult && visibilityResult.visibility === 'private'){
            const updateVisibility = `UPDATE snippets SET visibility='public' WHERE snippet_id=? AND user_id=?`
            await db.run(updateVisibility,[id,user_id])
            response.status(200).json("Visibility Updated to public!!")
        }else if(visibilityResult && visibilityResult.visibility === 'public'){
            const updateVisibility = `UPDATE snippets SET visibility='private' WHERE snippet_id=? AND user_id=?`
            await db.run(updateVisibility,[id,user_id])
            response.status(200).json("Visibility Updated to private!!")
        }else{
            response.status(400).json("You are not allowed to change this")
        }
        
    }
    catch(error){
        console.error("Cannot update visibility", error)
        response.status(500).json({error:error.message})
    }
})

module.exports = app
















































