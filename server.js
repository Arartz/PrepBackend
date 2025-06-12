import express from 'express'
import mysql from 'mysql'
import cors from 'cors'
import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'
import crypto from 'crypto'
import nodemailer from 'nodemailer'


const PORT = 4000
const app = express()
app.use(cors())
app.use(express.json())

const JWT_SECRET = 'your-secret-key' // In production, use environment variable

// Authentication middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(' ')[1]
    
    if (!token) return res.status(401).json({ error: 'Access denied' })
    
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid token' })
        req.user = user
        next()
    })
}

app.listen(PORT, () => {
    console.log('Server Running At port: ', PORT)
})

const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'preprush'
})

db.connect((err) => {
    if(err) return console.log(err)
    return console.log('database connected')
})

// Authentication routes
app.post('/register', async (req, res) => {
    const { name, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);

    const sql = "INSERT INTO users (name, password) VALUES (?, ?)";
    db.query(sql, [name, hashedPassword], (err, data) => {
        if (err) return res.status(400).json({ error: err.message });
        return res.json({ message: 'User registered successfully' });
    });
});


app.post('/login', (req, res) => {
    const { name, password } = req.body
    
    const sql = "SELECT * FROM users WHERE name = ?"
    db.query(sql, [name], async (err, data) => {
        if(err) return res.status(400).json({ error: err.message })
        if(data.length === 0) return res.status(400).json({ error: 'User not found' })
        
        const user = data[0]
        const validPassword = await bcrypt.compare(password, user.password)
        if(!validPassword) return res.status(400).json({ error: 'Invalid password' })
        
        const token = jwt.sign({ id: user.id, name: user.name }, JWT_SECRET)
        res.json({ token, name : user.name })
    })
})

// Module Management

app.get('/get/modules', (req, res) => {
    const sql = "SELECT * FROM modules";
    db.query(sql, (err, data) => {
        if(err) return res.send(err)
        return res.json(data)
    })
})

app.get('/get/lessons/:id', (req, res) => {
    const moduleId = req.params.id
    const sql = `
        SELECT 
            l.lesson_id,
            l.title,
            l.module_id,
            m.module_name,
            (SELECT COUNT(*) FROM questions q WHERE q.lesson_id = l.lesson_id) as question_count
        FROM lessons l
        JOIN modules m ON l.module_id = m.module_id
        WHERE l.module_id = ?
        ORDER BY l.title
    `
    db.query(sql, [moduleId], (err, data) => {
        if(err) return res.status(400).json({ error: err.message })
        return res.json(data)
    })
})

app.get('/get/questions/:id', (req, res) => {
    const sql = `
        SELECT q.*, GROUP_CONCAT(
            JSON_OBJECT(
                'id', o.id,
                'content', o.content,
                'is_correct', o.is_correct
            )
        ) as options
        FROM questions q
        LEFT JOIN options o ON q.id = o.question_id
        WHERE q.lesson_id = ?
        GROUP BY q.id
        ORDER BY q.difficulty_level
    `
    db.query(sql, [req.params.id], (err, data) => {
        if(err) return res.send(err)
        // Parse the options string into an array of objects
        const questions = data.map(q => ({
            ...q,
            options: JSON.parse(`[${q.options}]`)
        }))
        return res.json(questions)
    })
})

app.get('/get/option/:qid', (req, res) => {
    const sql = "SELECT * FROM options WHERE question_id = ?"
    db.query(sql, [req.params.qid], (err, data) => {
        if(err) return res.send(err)
        return res.json(data)
    })
})

// Progress Tracking
app.get('/get/overall-progress', authenticateToken, (req, res) => {
    const userId = req.user.id
    const sql = `
        SELECT 
            (SUM(p.correct_count) * 100.0 / (SUM(p.attempted_count) * 5)) as progress
        FROM progress p
        WHERE p.user_id = ?
    `
    db.query(sql, [userId], (err, data) => {
        if(err) return res.status(400).json({ error: err.message })
        return res.json({ progress: Math.round(data[0].progress || 0) })
    })
})

app.get('/get/module-progress', authenticateToken, (req, res) => {
    const userId = req.user.id
    const sql = `
        SELECT 
            m.module_id,
            m.module_name,
            (SUM(p.correct_count) * 100.0 / (SUM(p.attempted_count) * 5)) as progress
        FROM modules m
        LEFT JOIN lessons l ON m.module_id = l.module_id
        LEFT JOIN progress p ON l.id = p.lesson_id AND p.user_id = ?
        GROUP BY m.module_id, m.module_name
    `
    db.query(sql, [userId], (err, data) => {
        if(err) return res.status(400).json({ error: err.message })
        const progress = data.map(item => ({
            ...item,
            progress: Math.round(item.progress || 0)
        }))
        return res.json(progress)
    })
})

app.post('/save/progress', authenticateToken, async (req, res) => {
    try {
        const { lessonId, score, totalQuestions, grade } = req.body
        const userId = req.user.id

        console.log('Received progress save request:', {
            userId,
            lessonId,
            score,
            totalQuestions,
            grade
        })

        // Validate input
        if (!lessonId || score === undefined || !totalQuestions || !grade) {
            return res.status(400).json({ 
                error: 'Missing required fields',
                details: 'lessonId, score, totalQuestions, and grade are required'
            })
        }

        // First check if the lesson exists and get its module_id
        const lessonQuery = 'SELECT module_id FROM lessons WHERE lesson_id = ?'
        console.log('Executing lesson query:', lessonQuery, 'with lessonId:', lessonId)
        
        const lessonResult = await new Promise((resolve, reject) => {
            db.query(lessonQuery, [lessonId], (err, results) => {
                if (err) {
                    console.error('Error querying lesson:', err)
                    reject(err)
                    return
                }
                console.log('Lesson query results:', results)
                resolve(results)
            })
        })

        if (!lessonResult || lessonResult.length === 0) {
            console.error('Lesson not found:', lessonId)
            return res.status(404).json({ 
                error: 'Lesson not found',
                details: `No lesson found with ID: ${lessonId}`
            })
        }

        const moduleId = lessonResult[0].module_id
        console.log('Found module_id:', moduleId)

        // Get existing progress
        const existingProgressQuery = 'SELECT * FROM progress WHERE user_id = ? AND lesson_id = ?'
        console.log('Executing existing progress query:', existingProgressQuery)
        
        const existingProgressResult = await new Promise((resolve, reject) => {
            db.query(existingProgressQuery, [userId, lessonId], (err, results) => {
                if (err) {
                    console.error('Error querying existing progress:', err)
                    reject(err)
                    return
                }
                console.log('Existing progress results:', results)
                resolve(results)
            })
        })

        let newScore, newTotalQuestions, newProgressPercentage

        if (existingProgressResult.length > 0) {
            // Add to existing progress
            const existingProgress = existingProgressResult[0]
            newScore = existingProgress.score + score
            newTotalQuestions = existingProgress.total_questions + totalQuestions
            newProgressPercentage = (newScore / newTotalQuestions) * 100

            console.log('Updating existing progress:', {
                userId,
                lessonId,
                oldScore: existingProgress.score,
                newScore,
                oldTotal: existingProgress.total_questions,
                newTotal: newTotalQuestions,
                newProgressPercentage
            })

            const updateQuery = 'UPDATE progress SET score = ?, total_questions = ?, grade = ?, progress_percentage = ?, updated_at = CURRENT_TIMESTAMP WHERE user_id = ? AND lesson_id = ?'
            await new Promise((resolve, reject) => {
                db.query(updateQuery, [newScore, newTotalQuestions, grade, newProgressPercentage, userId, lessonId], (err) => {
                    if (err) {
                        console.error('Error updating progress:', err)
                        reject(err)
                        return
                    }
                    resolve()
                })
            })
        } else {
            // Create new progress record
            newScore = score
            newTotalQuestions = totalQuestions
            newProgressPercentage = (score / totalQuestions) * 100

            console.log('Creating new progress record:', {
                userId,
                lessonId,
                score: newScore,
                totalQuestions: newTotalQuestions,
                progressPercentage: newProgressPercentage
            })

            const insertQuery = 'INSERT INTO progress (user_id, lesson_id, score, total_questions, grade, progress_percentage) VALUES (?, ?, ?, ?, ?, ?)'
            await new Promise((resolve, reject) => {
                db.query(insertQuery, [userId, lessonId, newScore, newTotalQuestions, grade, newProgressPercentage], (err) => {
                    if (err) {
                        console.error('Error inserting progress:', err)
                        reject(err)
                        return
                    }
                    resolve()
                })
            })
        }

        // Calculate module progress
        const moduleProgressQuery = 'SELECT AVG(progress_percentage) as module_progress FROM progress WHERE user_id = ? AND lesson_id IN (SELECT lesson_id FROM lessons WHERE module_id = ?)'
        console.log('Executing module progress query:', moduleProgressQuery)
        
        const moduleProgressResult = await new Promise((resolve, reject) => {
            db.query(moduleProgressQuery, [userId, moduleId], (err, results) => {
                if (err) {
                    console.error('Error calculating module progress:', err)
                    reject(err)
                    return
                }
                console.log('Module progress results:', results)
                resolve(results)
            })
        })

        const moduleProgressPercentage = moduleProgressResult[0]?.module_progress || 0

        // Calculate overall progress
        const overallProgressQuery = 'SELECT AVG(progress_percentage) as overall_progress FROM progress WHERE user_id = ?'
        console.log('Executing overall progress query:', overallProgressQuery)
        
        const overallProgressResult = await new Promise((resolve, reject) => {
            db.query(overallProgressQuery, [userId], (err, results) => {
                if (err) {
                    console.error('Error calculating overall progress:', err)
                    reject(err)
                    return
                }
                console.log('Overall progress results:', results)
                resolve(results)
            })
        })

        const overallProgressPercentage = overallProgressResult[0]?.overall_progress || 0

        console.log('Progress saved successfully:', {
            userId,
            lessonId,
            moduleId,
            score: newScore,
            totalQuestions: newTotalQuestions,
            progressPercentage: newProgressPercentage,
            moduleProgress: moduleProgressPercentage,
            overallProgress: overallProgressPercentage
        })

        res.json({ 
            success: true, 
            message: 'Progress saved successfully',
            progress: {
                lesson: newProgressPercentage,
                module: moduleProgressPercentage,
                overall: overallProgressPercentage,
                score: newScore,
                totalQuestions: newTotalQuestions
            }
        })
    } catch (err) {
        console.error('Error saving progress:', err)
        res.status(500).json({ 
            error: 'Failed to save progress',
            details: err.message
        })
    }
})

// Get questions excluding previously correct answers
app.get('/get/next-questions/:lessonId', authenticateToken, (req, res) => {
    const { lessonId } = req.params
    const userId = req.user.id

    console.log('Fetching questions for lesson:', lessonId, 'user:', userId)

    // Get user's progress for this lesson
    const progressSql = `
        SELECT progress_percentage
        FROM progress
        WHERE user_id = ? AND lesson_id = ?
        ORDER BY created_at DESC
        LIMIT 1
    `
    db.query(progressSql, [userId, lessonId], (err, progressData) => {
        if(err) {
            console.error('Error fetching progress:', err)
            return res.status(400).json({ error: err.message })
        }

        const progress = progressData[0]?.progress_percentage || 0
        let difficultyLevel = 'easy'
        
        // Adjust difficulty based on progress
        if(progress >= 80) difficultyLevel = 'hard'
        else if(progress >= 50) difficultyLevel = 'medium'

        console.log('User progress:', progress, 'Difficulty level:', difficultyLevel)

        // Get questions that were not answered correctly before
        const questionsSql = `
            SELECT q.*, GROUP_CONCAT(
                JSON_OBJECT(
                    'id', o.id,
                    'content', o.content,
                    'is_correct', o.is_correct
                )
            ) as options
            FROM questions q
            LEFT JOIN options o ON q.id = o.question_id
            WHERE q.lesson_id = ?
            AND q.difficulty_level = ?
            AND q.id NOT IN (
                SELECT DISTINCT q.id
                FROM questions q
                JOIN options o ON q.id = o.question_id
                JOIN progress p ON p.lesson_id = q.lesson_id
                WHERE p.user_id = ? 
                AND p.score = p.total_questions
                AND o.is_correct = 1
            )
            GROUP BY q.id
            ORDER BY RAND()
            LIMIT 5
        `

        db.query(questionsSql, [lessonId, difficultyLevel, userId], (err, data) => {
            if(err) {
                console.error('Error fetching questions:', err)
                return res.status(400).json({ error: err.message })
            }
            
            console.log('Found questions:', data.length)
            
            // Parse the options string into an array of objects
            const questions = data.map(q => ({
                ...q,
                options: JSON.parse(`[${q.options}]`)
            }))

            // If we don't have enough new questions, get some from previously correct ones
            if (questions.length < 5) {
                const remainingCount = 5 - questions.length
                console.log('Fetching additional questions:', remainingCount)
                
                const additionalQuestionsSql = `
                    SELECT q.*, GROUP_CONCAT(
                        JSON_OBJECT(
                            'id', o.id,
                            'content', o.content,
                            'is_correct', o.is_correct
                        )
                    ) as options
                    FROM questions q
                    LEFT JOIN options o ON q.id = o.question_id
                    WHERE q.lesson_id = ?
                    AND q.difficulty_level = ?
                    AND q.id IN (
                        SELECT DISTINCT q.id
                        FROM questions q
                        JOIN options o ON q.id = o.question_id
                        JOIN progress p ON p.lesson_id = q.lesson_id
                        WHERE p.user_id = ? 
                        AND p.score = p.total_questions
                        AND o.is_correct = 1
                    )
                    GROUP BY q.id
                    ORDER BY RAND()
                    LIMIT ?
                `

                db.query(additionalQuestionsSql, [lessonId, difficultyLevel, userId, remainingCount], (err, additionalData) => {
                    if(err) {
                        console.error('Error fetching additional questions:', err)
                        return res.status(400).json({ error: err.message })
                    }
                    
                    const additionalQuestions = additionalData.map(q => ({
                        ...q,
                        options: JSON.parse(`[${q.options}]`)
                    }))

                    console.log('Found additional questions:', additionalQuestions.length)
                    return res.json([...questions, ...additionalQuestions])
                })
            } else {
                return res.json(questions)
            }
        })
    })
})

// Get user's progress
app.get('/get/progress', authenticateToken, (req, res) => {
    const userId = req.user.id
    const query = `
        SELECT 
            p.*,
            m.module_name,
            m.module_id,
            l.title as lesson_title,
            l.lesson_id
        FROM progress p
        JOIN lessons l ON p.lesson_id = l.lesson_id
        JOIN modules m ON l.module_id = m.module_id
        WHERE p.user_id = ?
        ORDER BY p.created_at DESC
    `
    db.query(query, [userId], (err, results) => {
        if (err) {
            console.log(err)
            res.status(500).json({ error: 'Failed to fetch progress' })
            return
        }
        console.log('Progress results:', results) // Debug log
        res.json(results)
    })
})