if(process.env.NODE_ENV!=='production'){
    require('dotenv').config()
}
// console.log(process.env.CLOUDINARY_SECRET)
//remember to listen to different ports in this app and on the main
//changes applied to port 3000 on this app may force changes on the other app also listening to 3000

const express=require('express')
const cors=require('cors')
const Book=require('./models/library_model')
const Comment=require('./models/comments_model')
const User=require('./models/user_model')
const mongoose=require('mongoose')
const ejsMate=require('ejs-mate')
const methodOverride=require('method-override')
const session=require('express-session')
const cookieParser = require('cookie-parser'); // CSRF Cookie parsing
const bodyParser = require('body-parser'); // CSRF Body parsing
const passport=require('passport')
const passportLocal=require('passport-local')
const multer=require('multer')
const MongoDBStore=require('connect-mongodb-session')(session)
const helmet= require('helmet')
const crypto= require('crypto');
const csrf = require('csurf');
const app=express()
const dbURL=process.env.MONGO_URL


const nonce = crypto.randomBytes(16).toString('base64');
console.log(nonce)


const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');

cloudinary.config({
    cloud_name:process.env.CLOUDINARY_CLOUD_NAME,
    api_key:process.env.CLOUDINARY_KEY,
    api_secret:process.env.CLOUDINARY_SECRET
})
console.log(process.env.CLOUDINARY_CLOUD_NAME)

const storage=new CloudinaryStorage({
    cloudinary,
    //upload things to
   params:{
    folder:'library',
    allowedFormats:['jpeg,jpg,pdf']
   }
})

const handleCloudinaryUploadError = (err, req, res, next) => {
    if (err instanceof multer.MulterError) {
        // Multer error
        console.error('Multer Error:', err.message);
        // Handle the error as needed
    } else if (err) {
        // Cloudinary error
        console.error('Cloudinary Error:', err.message);
        // Handle the error as needed
    } else if (!req.file) {
        // No file uploaded
        console.error('No file uploaded.');
        // Handle the error as needed
    }
    next();
};


app.use(function(req, res, next) {
    // Set multiple allowed origins in the Access-Control-Allow-Origin header
    res.setHeader('Access-Control-Allow-Origin', 'https://securelibraryapp1.onrender.com');

    // Request methods you wish to allow
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, PATCH, DELETE');

    // Request headers you wish to allow
    res.setHeader('Access-Control-Allow-Headers', 'X-Requested-With,content-type');

    // Set to true if you need the website to include cookies in the requests sent
    // to the API (e.g. in case you use sessions)
    res.setHeader('Access-Control-Allow-Credentials', true);

    // Pass to next layer of middleware
    next();
});



const upload=multer({storage})
const {librarySchema,commentsSchema}=require('./schemas')
const flash=require('connect-flash')
const ExpErr=require('./errorHandlers/customExpressError')







//'
//
//'mongodb://localhost:27017/booksDB'
//

mongoose.connect(dbURL, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => {
        console.log("CONNECTION OPEN!!!")
    })
    .catch(err => {
        console.log("AN ERROR OCCURED!!!!")
        console.log(err)
    })

app.use(express.urlencoded({extended:true}))
app.use(methodOverride('_method'))
app.engine('ejs', ejsMate )
app.use(express.static('public'))//serve public files
const csrfProtect = csrf({ cookie: true,secret:process.env.CSRF_SECRET})
app.use(cookieParser());
app.use(bodyParser.urlencoded({ extended: false }));



const secret = process.env.SECRET || 'thisismysecret';


// process.env.MONGO_URL
const store = new MongoDBStore({
    uri: dbURL, // Use 'uri' instead of 'url'
    collection: 'sessions', // This specifies the name of the collection
    secret,
    touchAfter: 24 * 3600
});


store.on("error", function(e){
    console.log("session error " ,e )
})


app.set('trust proxy', 1);

app.use(session({
    store,
    name: 'session',
    secret,
    resave: false,
    saveUninitialized: true,
    cookie: {
        httpOnly: true,
        sameSite: 'none',
        secure:'true',
        expires: Date.now() + 1000 * 60 * 60 * 24 * 7,
        maxAge: 1000 * 60 * 60 * 24 * 7
    }
}));

app.use(flash());
app.use(helmet());


const scriptSrcUrls = [
    "https://cdn.jsdelivr.net/npm/@popperjs/core@2.9.2/dist/umd/popper.min.js",
    "https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/js/bootstrap.min.js",
    "https://unpkg.com/swiper@11.0.7/swiper-bundle.min.js",
    "https://unpkg.com",
    "https://code.jquery.com/jquery-3.6.0.min.js"
];
const styleSrcUrls = [
    "https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/css/bootstrap.min.css",
    "https://unpkg.com/swiper@11.0.7/swiper-bundle.min.css",
    "https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.3/css/all.min.css",
    "https://unpkg.com"


];

const fontSrcUrls = ["https://cdnjs.cloudflare.com"];
app.use(
    helmet.contentSecurityPolicy({
        directives: {
            defaultSrc: [],
            connectSrc: ["'self'"],
            scriptSrc: ["'self'" ,...scriptSrcUrls], // Include 'self' and 'unsafe-inline' for scripts
            // `'nonce-${nonce}'`
            // , "'unsafe-inline'"
            styleSrc: ["'self'",`'nonce-${nonce}'`, ...styleSrcUrls],
            // Include 'self', 'unsafe-inline', and nonce with proper syntax
            workerSrc: ["'self'", "blob:"],
            childSrc: ["blob:"],
            objectSrc: [],
            imgSrc: [
                "'self'",
                "blob:",
                "data:",
                "https://res.cloudinary.com/dlg6yu0cn/", 
                "https://images.unsplash.com",
            ],
            fontSrc: ["'self'", ...fontSrcUrls],
        },
    })
);


console.log()

//passport method configuration
app.use(passport.initialize())
app.use(passport.session())
passport.use(new passportLocal(User.authenticate()))
//how to store and unstore user in a session
passport.serializeUser(User.serializeUser())
passport.deserializeUser(User.deserializeUser())

app.use(function(req,res,next){
    res.locals.error=req.flash("error");
    res.locals.success=req.flash("success");
    res.locals.sessionUser=req.user
    next()
})

const authorizeAction = (req, res, next) => {
    if (!req.isAuthenticated()) {
        req.flash('error', 'You need to login first')
        return res.redirect('/login');
    }
    next();
};

const validateBook=(req,res,next)=>{
    const{error}=librarySchema.validate(req.body)
    if(error){
    throw new ExpErr(error,404)
    }
    else{
        
    next()
    }
    }
    





const validateComment=(req,res,next)=>{
    const{error}=commentsSchema.validate(req.body)
    if(error){
        throw new ExpErr(error,404)
    }
    else{
        next()
    }
}




const isBookOwner = async (req, res, next) => {
    const { id } = req.params;
    const book = await Book.findById(id);

    // Convert ObjectID to string for comparison
    const bookUserId = book.bookUser.toString();
    const loggedInUserId = req.user._id.toString();

    if (bookUserId !== loggedInUserId) {
        next( new ExpErr('You do not have permission for the operation',404))
        
        
    } else {
        next();
    }
};

const isCommentOwner = async (req, res, next) => {
    const { commentId } = req.params;
    const comment = await Comment.findById(commentId);

    // Convert ObjectID to string for comparison
    const commentUserId = comment.bookUser.toString();
    const loggedInUserId = req.user._id.toString();

    if (commentUserId !== loggedInUserId) {
        next( new ExpErr('You do not have permission for the operation',404))
        
        
    } else {
        next();
    }
};





//library routes
app.get('/',(req,res)=>{
    res.render('home.ejs',{nonce:nonce})
})

app.get('/library',csrfProtect, async(req,res)=>{
    const book=await Book.find()
    res.render('index.ejs', {csrfToken: req.csrfToken(),book,nonce:nonce})
    
})
//the parameter of upload should match the name atr on the form
app.post('/library', upload.array('image'), authorizeAction, validateBook,handleCloudinaryUploadError,csrfProtect, async (req, res, next) => {
    const csrfTokenReceived = req.body._csrf;
    

    console.log('CSRF token received from the client:', csrfTokenReceived);
    

    try {
        const book = new Book(req.body.library);
        const jpgFiles = req.files.filter(file => file.path.endsWith('.jpg'));
        if (jpgFiles.length > 4||book.image.length>5) {
            return next(new ExpErr('A maximum number of 5 images is allowed; a maximum of 4 jpg files allowed', 404));
        }

        if (jpgFiles.length <= 0) {
            return next(new ExpErr('At least one image is needed', 404));
        }

        book.image = req.files.map(f => ({ url: f.path, filename: f.filename }));
        
        book.bookUser = req.user._id;

        await book.save();
       console.log('newly created book')
       console.log(book)

        req.flash('success', 'Created successfully');

        res.redirect(`/library`);
    } catch (error) {
        console.error('Error in creating a book:', error);
        req.flash('error', 'Error creating a book');
        next(error);
    }
});


app.get('/library/new',csrfProtect, authorizeAction, (req, res) => {
    console.log(`csrftoken sent by the server fot the /new route:${req.csrfToken()}`)
    res.render('new.ejs', {csrfToken: req.csrfToken(), nonce: nonce });
});


app.get('/library/:id',csrfProtect, async (req, res, next) => {
    const { id } = req.params;
    try {
        const book = await Book.findById(id)
            .populate({
                path: 'comments',
                populate: [
                    { path: 'bookUser' },
                    { path: 'date' } // Assuming 'date' is a reference field in 'comments'
                ],
            })
            .populate('bookUser');

        console.log('Book:', book); // Log the entire book object

        res.render('show.ejs', {csrfToken: req.csrfToken(), book, nonce:nonce});
    } catch (e) {
        next(e);
    }
});




app.put('/library/:id', upload.array('image'),authorizeAction,isBookOwner,validateBook,csrfProtect, async(req,res,next)=>{
    
    const{id}=req.params

    const book=await Book.findByIdAndUpdate(id,req.body.library)
    console.log(book.bookUser)
    console.log(req.user._id)
   
    if (!req.files) {
        return res.status(400).send('No files were uploaded.');
    }
    const img=req.files.map(f=>({url:f.path, filename:f.filename}))
    book.image.push(...img)
    console.log('req.files: to be deleted from the project')
    console.log(req.body.deleteImages )
  
    if(req.body.deleteImages){
        
        const allImg=book.image.length-req.body.deleteImages.length
        const jpgImg=book.image.filter(i=>i.url.endsWith('.jpg')).length-req.body.deleteImages.filter(image => image.endsWith('.jpg')).length;
   
        if(allImg>5||jpgImg>4){
            return next(new ExpErr('number of files/images exeeded: maximum of 5 files allowed; maximum of 4 jpg file allowed', 404))
        }
    }
    else{
       
        const allImg=book.image.length
        const jpgImg=book.image.filter(i=>i.url.endsWith('.jpg'))
        if(allImg>5||jpgImg>4){
            return next(new ExpErr('number of files/images exeeded: maximum of 5 files allowed; maximum of 4 jpg file allowed', 404))
        }
    }
    
    
    
    await book.save()
    
    if(req.body.deleteImages){
        const jpgFiles = book.image.filter(img => img.url.endsWith('.jpg'));
        console.log('count of jpg file:',jpgFiles.length)
        const jpgDeleteCount = req.body.deleteImages.filter(image => image.endsWith('.jpg')).length;
        console.log(req.body.deleteImages.filter(image => image.endsWith('.jpg')))
        console.log(jpgDeleteCount)
        console.log('to be deleted')
        console.log(req.body.deleteImages)
        const remainingJpgFiles = jpgFiles.length - jpgDeleteCount;
        console.log('remaining jpg files', remainingJpgFiles)
        if (remainingJpgFiles < 1) {
            // If there's only one image and the user is trying to delete it, throw an error
            return next(new ExpErr('At least one image is needed', 404));
        }
        //added
        
        //end
        for(let url of req.body.deleteImages){
            await cloudinary.uploader.destroy(url)
        }
        console.log('image to delete')
        console.log(req.body.deleteImages)
       
        await book.updateOne({$pull:{image:{url:{$in:req.body.deleteImages}}}})

        await book.save()
    }
    console.log('*************8')
    console.log(book)
    req.flash('success','updated successfully')
    res.redirect(`/library/${book._id}`)
    
})

app.delete('/library/:id',authorizeAction, isBookOwner, async(req,res)=>{
    const{id}=req.params
    const book=await Book.findByIdAndDelete(id)
    req.flash('success', 'successfully deleted')
    res.redirect('/library')
})

app.get('/library/:id/edit', authorizeAction,isBookOwner,csrfProtect, async(req,res)=>{
    const{id}=req.params
    const book=await Book.findById(id)
    res.render('edit.ejs',{csrfToken: req.csrfToken(),book,nonce:nonce})

  
})

app.post('/search',csrfProtect ,async (req, res, next) => {
    console.log(req.body)
    // Use a regular expression to search for books with titles containing the search term
    const searchTerm = req.body.value;
    
    const regex = new RegExp(searchTerm, 'i'); // 'i' flag makes the search case-insensitive
    
    try {
      const searchBy=req.body.cat
      if(searchBy==='author'){
          const books = await Book.find({ author: { $regex: regex } });
          if (books.length === 0) {
            next(new ExpErr('No books found', 404));
          } else {
            res.render('searchedBook.ejs', {csrfToken: req.csrfToken(), books,nonce:nonce });
          }
      }else
      if(searchBy==='title'){
        const books = await Book.find({ title: { $regex: regex } });
        if (books.length === 0) {
          next(new ExpErr('No books found', 404));
        } else {
          res.render('searchedBook.ejs', {csrfToken: req.csrfToken(), books,nonce:nonce });
        }
    }
    else
    if(searchBy==='ISBN'){
        const books = await Book.find({ author: { $regex: regex } });
        if (books.length === 0) {
          next(new ExpErr('No books found', 404));
        } else {
          res.render('searchedBook.ejs', {csrfToken: req.csrfToken(), books,nonce:nonce});
        }
    }else
    if(searchBy==='category'){
        const books = await Book.find({ category: { $regex: regex } });
        if (books.length === 0) {
          next(new ExpErr('No books found', 404));
        } else {
          res.render('searchedBook.ejs', {csrfToken: req.csrfToken(), books,nonce:nonce });
        }
    }


       
      
     
    } catch (err) {
      next(err); // Pass any database-related errors to the error handler
    }
  });













  
  

// app.post('/search',async(req,res,next)=>{
//     const book=await Book.findOne({title:req.body.search})
//     if(!book){
//         next(new ExpErr('Book not found',404))
//     }
//     else{
//         res.render('show.ejs',{book})
//     }
// })

//comments routes

app.post('/library/:id/comments',authorizeAction,csrfProtect,async(req,res)=>{
    const{id}=req.params
    console.log(req.body.comment)
    const book=await Book.findById(id)
    const comment=new Comment(req.body.comment)
    comment.bookUser=req.user._id
    book.comments.push(comment)
    await book.save()
    await comment.save()
    res.redirect(`/library/${id}`)
})


app.delete('/library/:id/comments/:commentId',authorizeAction,isCommentOwner,csrfProtect, async(req,res)=>{
    const{id, commentId}=req.params
    const book=await Book.findByIdAndUpdate(id, { $pull: { comments: commentId } });
    await Comment.findByIdAndDelete(commentId);
    await book.save()
    req.flash('success', 'comment deleted successfully')
    res.redirect(`/library/${id}`)
    


})

//user routes

app.get('/register', csrfProtect, (req,res)=>{
res.render('registerForm.ejs', {csrfToken: req.csrfToken(),nonce:nonce})
})

app.post('/register',csrfProtect, async (req, res,next) => {
    try{
        const { username, email, password } = req.body;

    const user = new User({ username, email });

    const regUser = await User.register(user, password);

    req.login(regUser, (err) => {
        if (err) {
            console.error('Error during login:', err);
            return res.redirect('/register'); // Redirect to an error page or login page
        }
        req.flash('success','Welcome to our library! Enjoy:)')
        res.redirect('/library');
    });
    }
    catch(err){
        next(err)
    }
});

app.get('/login', csrfProtect, (req,res)=>{
    res.render('loginForm.ejs',{csrfToken: req.csrfToken(),nonce:nonce})
    const csrfTokenSentByServer = req.csrfToken();
    console.log('CSRF token sent from the server:', csrfTokenSentByServer);
})

app.post('/login', passport.authenticate('local', { failureRedirect: '/login' , failureFlash:true}), (req,res)=>{
    const csrfTokenReceived = req.body._csrf;
    

    console.log('CSRF token received from the client:', csrfTokenReceived);
    
    console.log(req.session.messages)
  
    req.flash('success','Successfully logged in')
    res.redirect('/library')
    
    
})

app.get('/logout',(req,res)=>{
    req.logOut((err)=>{
        if(err){
            console.log(err)
        }
        req.flash('success', 'successfully logged out')
        res.redirect('/library')
    })
})


app.get('/userInfo', authorizeAction,async(req,res)=>{
    const user=req.user
    const books = await Book.find({ bookUser: user._id });
    res.render('userInfo.ejs',{user, books, nonce:nonce})
})

app.delete('/userInfo',authorizeAction,async(req,res)=>{
    console.log(req.user._id)
    await Comment.deleteMany({bookUser: req.user._id})
    await Book.deleteMany({bookUser: req.user._id})
    await User.findByIdAndDelete(req.user._id)
    req.flash('success', 'Account deleted succesfully! All your books and comments have been deleted')
    res.redirect('/library')
})


// app.get('/error', (req,res)=>{
//     throw new ExpErr('not allowed',404)
// })

app.all('*',(req,res)=>{
    throw new ExpErr('Page Not Found', 404)

})

app.use((err, req, res, next) => {
    const{message='opss, failed...'}=err
    res.render('error.ejs', {err,nonce:nonce})
  })



app.listen(3000,()=>{
    console.log('listening on port 3000') 
})