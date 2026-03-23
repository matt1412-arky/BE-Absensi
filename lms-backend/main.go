package main

import (
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var db *gorm.DB
var jwtSecret = []byte(getEnv("JWT_SECRET", "gonzaga-secret-key-2024"))

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// ─── Models ──────────────────────────────────────────────────────────────────

type User struct {
	ID           uint      `gorm:"primaryKey" json:"id"`
	Username     string    `gorm:"uniqueIndex;not null" json:"username"`
	PasswordHash string    `gorm:"not null" json:"-"`
	Role         string    `gorm:"not null" json:"role"` // superadmin | admin | student
	Name         string    `json:"name"`
	ClassID      *uint     `json:"class_id"` // only for students
	CreatedAt    time.Time `json:"created_at"`
}

type Class struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	Name      string    `gorm:"uniqueIndex;not null" json:"name"` // e.g. "X-A", "XI-IPA"
	CreatedAt time.Time `json:"created_at"`
}

type Student struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	UserID    uint      `json:"user_id"`
	ClassID   uint      `json:"class_id"`
	Name      string    `json:"name"`
	Points    int       `json:"points"`
	CreatedAt time.Time `json:"created_at"`
	// Relations
	Class Class `gorm:"foreignKey:ClassID" json:"class,omitempty"`
}

type Attendance struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	StudentID uint      `json:"student_id"`
	ClassID   uint      `json:"class_id"`
	Date      string    `json:"date"`   // YYYY-MM-DD
	Status    string    `json:"status"` // present | absent | sick | permission
	CreatedAt time.Time `json:"created_at"`
}

type Grade struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	StudentID uint      `json:"student_id"`
	ClassID   uint      `json:"class_id"`
	Subject   string    `json:"subject"`
	Score     float64   `json:"score"`
	Type      string    `json:"type"` // tugas | ulangan | uts | uas
	Date      string    `json:"date"`
	Notes     string    `json:"notes"`
	CreatedAt time.Time `json:"created_at"`
}

type Schedule struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	ClassID   uint      `json:"class_id"`
	AdminID   uint      `json:"admin_id"` // which teacher
	Subject   string    `json:"subject"`
	Day       int       `json:"day"`      // 1=Monday..7=Sunday
	TimeSlot  string    `json:"time"`     // "08:30"
	EndTime   string    `json:"end_time"` // "09:30"
	CreatedAt time.Time `json:"created_at"`
	// Relations
	Class Class `gorm:"foreignKey:ClassID" json:"class,omitempty"`
}

// ─── JWT ─────────────────────────────────────────────────────────────────────

type Claims struct {
	UserID   uint   `json:"user_id"`
	Username string `json:"username"`
	Role     string `json:"role"`
	Name     string `json:"name"`
	jwt.RegisteredClaims
}

func generateToken(user User) (string, error) {
	claims := Claims{
		UserID:   user.ID,
		Username: user.Username,
		Role:     user.Role,
		Name:     user.Name,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

func parseToken(tokenStr string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	if err != nil {
		return nil, err
	}
	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}
	return nil, jwt.ErrSignatureInvalid
}

// ─── Middleware ───────────────────────────────────────────────────────────────

func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		auth := c.GetHeader("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "missing token"})
			c.Abort()
			return
		}
		claims, err := parseToken(strings.TrimPrefix(auth, "Bearer "))
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			c.Abort()
			return
		}
		c.Set("claims", claims)
		c.Next()
	}
}

func roleMiddleware(roles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims := c.MustGet("claims").(*Claims)
		for _, r := range roles {
			if claims.Role == r {
				c.Next()
				return
			}
		}
		c.JSON(http.StatusForbidden, gin.H{"error": "access denied"})
		c.Abort()
	}
}

func getClaims(c *gin.Context) *Claims {
	return c.MustGet("claims").(*Claims)
}

// ─── Main ─────────────────────────────────────────────────────────────────────

func main() {
	dsn := getEnv("DATABASE_URL", "host=localhost user=postgres password=123 dbname=gonzaga_lms port=5432 sslmode=disable")

	var err error
	db, err = gorm.Open(postgres.New(postgres.Config{
		DSN:                  dsn,
		PreferSimpleProtocol: true, // disable prepared statements
	}), &gorm.Config{})
	if err != nil {
		panic("failed to connect db: " + err.Error())
	}

	db.AutoMigrate(&User{}, &Class{}, &Student{}, &Attendance{}, &Grade{}, &Schedule{})

	// Seed superadmin - hanya buat jika belum ada, TIDAK update password
	var count int64
	db.Model(&User{}).Where("username = ?", "superadmin").Count(&count)
	if count == 0 {
		password := getEnv("SUPERADMIN_PASSWORD", "superadmin123")
		hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		db.Create(&User{
			Username:     "superadmin",
			PasswordHash: string(hash),
			Role:         "superadmin",
			Name:         "Super Admin",
		})
		println("✅ Superadmin created")
	} else {
		println("ℹ️  Superadmin already exists")
	}

	r := gin.Default()
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
	}))

	// Public
	r.POST("/api/auth/login", handleLogin)
	r.GET("/", func(c *gin.Context) { c.String(200, "Gonzaga LMS Backend ✓") })

	auth := r.Group("/api", authMiddleware())
	{
		auth.GET("/me", handleMe)
		auth.PUT("/auth/change-password", handleChangePassword)

		// ── Superadmin only ──────────────────────────────────────────────
		sa := auth.Group("", roleMiddleware("superadmin"))
		{
			// Users management
			sa.GET("/users", getUsers)
			sa.POST("/users", createUser)
			sa.PUT("/users/:id", updateUser)
			sa.DELETE("/users/:id", deleteUser)
			sa.PUT("/users/:id/password", handleAdminChangePassword)

			// Classes management
			sa.POST("/classes", createClass)
			sa.PUT("/classes/:id", updateClass)
			sa.DELETE("/classes/:id", deleteClass)
		}

		// ── Superadmin + Admin ───────────────────────────────────────────
		adm := auth.Group("", roleMiddleware("superadmin", "admin"))
		{
			adm.GET("/classes", getClasses)
			adm.GET("/classes/:id/students", getStudentsByClass)

			adm.GET("/students", getStudents)
			adm.POST("/students", createStudent)
			adm.PUT("/students/:id", updateStudent)
			adm.DELETE("/students/:id", deleteStudent)

			adm.POST("/attendance", createOrUpdateAttendance)
			adm.GET("/attendance", getAttendance)

			adm.GET("/grades", getGrades)
			adm.POST("/grades", createGrade)
			adm.PUT("/grades/:id", updateGrade)
			adm.DELETE("/grades/:id", deleteGrade)

			adm.GET("/schedules", getSchedules)
			adm.POST("/schedules", createSchedule)
			adm.DELETE("/schedules/:id", deleteSchedule)

			adm.GET("/stats", getStats)
			adm.GET("/dashboard/admin", getDashboardAdmin)
		}

		// ── Student ──────────────────────────────────────────────────────
		stu := auth.Group("", roleMiddleware("student"))
		{
			stu.GET("/student/me", getMyStudentProfile)
			stu.GET("/student/attendance", getMyAttendance)
			stu.GET("/student/grades", getMyGrades)
			stu.GET("/student/dashboard", getDashboardStudent)
		}
	}

	port := getEnv("PORT", "8080")
	r.Run(":" + port)
}

// ─── Auth ─────────────────────────────────────────────────────────────────────

func handleLogin(c *gin.Context) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := c.BindJSON(&body); err != nil {
		c.JSON(400, gin.H{"error": "invalid payload"})
		return
	}
	var user User
	if err := db.Where("username = ?", body.Username).First(&user).Error; err != nil {
		c.JSON(401, gin.H{"error": "username atau password salah"})
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(body.Password)); err != nil {
		c.JSON(401, gin.H{"error": "username atau password salah"})
		return
	}
	token, err := generateToken(user)
	if err != nil {
		c.JSON(500, gin.H{"error": "gagal generate token"})
		return
	}
	c.JSON(200, gin.H{
		"token": token,
		"user": gin.H{
			"id":       user.ID,
			"username": user.Username,
			"name":     user.Name,
			"role":     user.Role,
			"class_id": user.ClassID,
		},
	})
}

func handleMe(c *gin.Context) {
	claims := getClaims(c)
	c.JSON(200, gin.H{
		"id":       claims.UserID,
		"username": claims.Username,
		"name":     claims.Name,
		"role":     claims.Role,
	})
}

// ─── Users (Superadmin) ───────────────────────────────────────────────────────

func getUsers(c *gin.Context) {
	var users []User
	db.Find(&users)
	c.JSON(200, users)
}

func createUser(c *gin.Context) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Name     string `json:"name"`
		Role     string `json:"role"` // superadmin | admin | student
		ClassID  *uint  `json:"class_id"`
	}
	if err := c.BindJSON(&body); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte(body.Password), bcrypt.DefaultCost)
	user := User{
		Username:     body.Username,
		PasswordHash: string(hash),
		Name:         body.Name,
		Role:         body.Role,
		ClassID:      body.ClassID,
	}
	if err := db.Create(&user).Error; err != nil {
		c.JSON(400, gin.H{"error": "username sudah dipakai"})
		return
	}
	// If student, also create Student record
	if body.Role == "student" && body.ClassID != nil {
		db.Create(&Student{
			UserID:  user.ID,
			ClassID: *body.ClassID,
			Name:    body.Name,
			Points:  0,
		})
	}
	c.JSON(201, user)
}

func updateUser(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var user User
	if err := db.First(&user, id).Error; err != nil {
		c.JSON(404, gin.H{"error": "user not found"})
		return
	}
	var body struct {
		Name     string `json:"name"`
		Password string `json:"password"`
		Role     string `json:"role"`
		ClassID  *uint  `json:"class_id"`
	}
	c.BindJSON(&body)
	if body.Name != "" {
		user.Name = body.Name
	}
	if body.Role != "" {
		user.Role = body.Role
	}
	if body.ClassID != nil {
		user.ClassID = body.ClassID
	}
	if body.Password != "" {
		hash, _ := bcrypt.GenerateFromPassword([]byte(body.Password), bcrypt.DefaultCost)
		user.PasswordHash = string(hash)
	}
	db.Save(&user)
	c.JSON(200, user)
}

func deleteUser(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	db.Delete(&User{}, id)
	db.Where("user_id = ?", id).Delete(&Student{})
	c.JSON(200, gin.H{"deleted": id})
}

// ─── Classes ──────────────────────────────────────────────────────────────────

func getClasses(c *gin.Context) {
	var classes []Class
	db.Find(&classes)
	c.JSON(200, classes)
}

func createClass(c *gin.Context) {
	var body struct {
		Name string `json:"name"`
	}
	c.BindJSON(&body)
	class := Class{Name: body.Name}
	if err := db.Create(&class).Error; err != nil {
		c.JSON(400, gin.H{"error": "nama kelas sudah ada"})
		return
	}
	c.JSON(201, class)
}

func updateClass(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var class Class
	db.First(&class, id)
	var body struct {
		Name string `json:"name"`
	}
	c.BindJSON(&body)
	class.Name = body.Name
	db.Save(&class)
	c.JSON(200, class)
}

func deleteClass(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	db.Delete(&Class{}, id)
	c.JSON(200, gin.H{"deleted": id})
}

func getStudentsByClass(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var students []Student
	db.Preload("Class").Where("class_id = ?", id).Find(&students)
	c.JSON(200, students)
}

// ─── Students ─────────────────────────────────────────────────────────────────

func getStudents(c *gin.Context) {
	classID := c.Query("class_id")
	var students []Student
	q := db.Preload("Class")
	if classID != "" {
		q = q.Where("class_id = ?", classID)
	}
	q.Find(&students)
	c.JSON(200, students)
}

func createStudent(c *gin.Context) {
	var body struct {
		Name    string `json:"name"`
		ClassID uint   `json:"class_id"`
		Points  int    `json:"points"`
	}
	if err := c.BindJSON(&body); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	if body.Name == "" {
		c.JSON(400, gin.H{"error": "nama tidak boleh kosong"})
		return
	}
	if body.ClassID == 0 {
		c.JSON(400, gin.H{"error": "kelas harus dipilih"})
		return
	}
	// Pastikan kelas ada
	var class Class
	if err := db.First(&class, body.ClassID).Error; err != nil {
		c.JSON(400, gin.H{"error": "kelas tidak ditemukan"})
		return
	}
	s := Student{
		Name:    body.Name,
		ClassID: body.ClassID,
		Points:  body.Points,
	}
	if err := db.Omit("Class").Create(&s).Error; err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(201, gin.H{
		"id":         s.ID,
		"user_id":    s.UserID,
		"class_id":   s.ClassID,
		"name":       s.Name,
		"points":     s.Points,
		"created_at": s.CreatedAt,
	})
}

func updateStudent(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var s Student
	db.First(&s, id)
	var body struct {
		Name    string `json:"name"`
		ClassID uint   `json:"class_id"`
		Points  int    `json:"points"`
	}
	c.BindJSON(&body)
	if body.Name != "" {
		s.Name = body.Name
	}
	if body.ClassID != 0 {
		s.ClassID = body.ClassID
	}
	s.Points = body.Points
	db.Save(&s)
	c.JSON(200, s)
}

func deleteStudent(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	db.Delete(&Student{}, id)
	c.JSON(200, gin.H{"deleted": id})
}

// ─── Attendance ───────────────────────────────────────────────────────────────

func createOrUpdateAttendance(c *gin.Context) {
	var body struct {
		StudentID uint   `json:"student_id"`
		ClassID   uint   `json:"class_id"`
		Date      string `json:"date"`
		Status    string `json:"status"`
	}
	if err := c.BindJSON(&body); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	// Points based on status
	pointsDelta := 0
	if body.Status == "present" {
		pointsDelta = 1
	}

	var existing Attendance
	res := db.Where("student_id = ? AND date = ?", body.StudentID, body.Date).First(&existing)
	if res.Error == nil {
		// Reverse old points
		if existing.Status == "present" {
			pointsDelta -= 1
		}
		existing.Status = body.Status
		existing.ClassID = body.ClassID
		db.Save(&existing)
	} else {
		a := Attendance{
			StudentID: body.StudentID,
			ClassID:   body.ClassID,
			Date:      body.Date,
			Status:    body.Status,
		}
		db.Create(&a)
	}

	// Update student points
	if pointsDelta != 0 {
		db.Model(&Student{}).Where("id = ?", body.StudentID).
			UpdateColumn("points", gorm.Expr("points + ?", pointsDelta))
	}

	c.JSON(200, gin.H{"success": true})
}

func getAttendance(c *gin.Context) {
	studentID := c.Query("student_id")
	classID := c.Query("class_id")
	start := c.Query("start")
	end := c.Query("end")

	var records []Attendance
	q := db.Order("date desc")
	if studentID != "" {
		q = q.Where("student_id = ?", studentID)
	}
	if classID != "" {
		q = q.Where("class_id = ?", classID)
	}
	if start != "" && end != "" {
		q = q.Where("date BETWEEN ? AND ?", start, end)
	}
	q.Find(&records)
	c.JSON(200, records)
}

// ─── Grades ───────────────────────────────────────────────────────────────────

func getGrades(c *gin.Context) {
	studentID := c.Query("student_id")
	classID := c.Query("class_id")
	var grades []Grade
	q := db.Order("date desc")
	if studentID != "" {
		q = q.Where("student_id = ?", studentID)
	}
	if classID != "" {
		q = q.Where("class_id = ?", classID)
	}
	q.Find(&grades)
	c.JSON(200, grades)
}

func createGrade(c *gin.Context) {
	var body Grade
	if err := c.BindJSON(&body); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	db.Create(&body)
	c.JSON(201, body)
}

func updateGrade(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var g Grade
	db.First(&g, id)
	c.BindJSON(&g)
	db.Save(&g)
	c.JSON(200, g)
}

func deleteGrade(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	db.Delete(&Grade{}, id)
	c.JSON(200, gin.H{"deleted": id})
}

// ─── Schedules ────────────────────────────────────────────────────────────────

func getSchedules(c *gin.Context) {
	claims := getClaims(c)
	var schedules []Schedule
	q := db.Preload("Class").Order("day asc, time_slot asc")
	if claims.Role == "admin" {
		q = q.Where("admin_id = ?", claims.UserID)
	}
	q.Find(&schedules)
	c.JSON(200, schedules)
}

func createSchedule(c *gin.Context) {
	var body struct {
		ClassID uint   `json:"class_id"`
		AdminID uint   `json:"admin_id"`
		Subject string `json:"subject"`
		Day     int    `json:"day"`
		Time    string `json:"time"`
		EndTime string `json:"end_time"`
	}
	c.BindJSON(&body)
	s := Schedule{
		ClassID:  body.ClassID,
		AdminID:  body.AdminID,
		Subject:  body.Subject,
		Day:      body.Day,
		TimeSlot: body.Time,
		EndTime:  body.EndTime,
	}
	db.Create(&s)
	c.JSON(201, s)
}

func deleteSchedule(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	db.Delete(&Schedule{}, id)
	c.JSON(200, gin.H{"deleted": id})
}

// ─── Stats & Dashboard ───────────────────────────────────────────────────────

func getStats(c *gin.Context) {
	classID := c.Query("class_id")
	start := c.Query("start")
	end := c.Query("end")
	if start == "" {
		start = time.Now().AddDate(0, -1, 0).Format("2006-01-02")
	}
	if end == "" {
		end = time.Now().Format("2006-01-02")
	}

	type StatRow struct {
		StudentID      uint    `json:"student_id"`
		Name           string  `json:"name"`
		ClassName      string  `json:"class_name"`
		Points         int     `json:"points"`
		PresentCount   int64   `json:"present_count"`
		TotalCount     int64   `json:"total_count"`
		AttendanceRate float64 `json:"attendance_rate"`
		AvgScore       float64 `json:"avg_score"`
	}

	var students []Student
	q := db.Preload("Class")
	if classID != "" {
		q = q.Where("class_id = ?", classID)
	}
	q.Find(&students)

	var out []StatRow
	for _, s := range students {
		var present, total int64
		db.Model(&Attendance{}).Where("student_id = ? AND date BETWEEN ? AND ? AND status = ?", s.ID, start, end, "present").Count(&present)
		db.Model(&Attendance{}).Where("student_id = ? AND date BETWEEN ? AND ?", s.ID, start, end).Count(&total)
		rate := 0.0
		if total > 0 {
			rate = float64(present) / float64(total) * 100
		}
		var avgScore float64
		db.Model(&Grade{}).Select("COALESCE(AVG(score), 0)").Where("student_id = ? AND date BETWEEN ? AND ?", s.ID, start, end).Scan(&avgScore)
		out = append(out, StatRow{
			StudentID:      s.ID,
			Name:           s.Name,
			ClassName:      s.Class.Name,
			Points:         s.Points,
			PresentCount:   present,
			TotalCount:     total,
			AttendanceRate: rate,
			AvgScore:       avgScore,
		})
	}
	c.JSON(200, gin.H{"students": out, "start": start, "end": end})
}

func getDashboardAdmin(c *gin.Context) {
	claims := getClaims(c)

	// Today's schedules
	today := int(time.Now().Weekday())
	if today == 0 {
		today = 7
	}
	var schedules []Schedule
	db.Preload("Class").Where("admin_id = ? AND day = ?", claims.UserID, today).Find(&schedules)

	// Recent attendance
	todayStr := time.Now().Format("2006-01-02")
	var todayAttendance []Attendance
	db.Where("date = ?", todayStr).Find(&todayAttendance)

	// Count per status
	statusCount := map[string]int64{}
	for _, s := range []string{"present", "absent", "sick", "permission"} {
		var cnt int64
		db.Model(&Attendance{}).Where("date = ? AND status = ?", todayStr, s).Count(&cnt)
		statusCount[s] = cnt
	}

	// Total students
	var totalStudents int64
	db.Model(&Student{}).Count(&totalStudents)

	c.JSON(200, gin.H{
		"today_schedules":  schedules,
		"today_attendance": statusCount,
		"total_students":   totalStudents,
		"date":             todayStr,
	})
}

func getDashboardStudent(c *gin.Context) {
	claims := getClaims(c)

	var student Student
	if err := db.Preload("Class").Where("user_id = ?", claims.UserID).First(&student).Error; err != nil {
		c.JSON(404, gin.H{"error": "profil siswa tidak ditemukan"})
		return
	}

	// Last 30 days attendance
	start := time.Now().AddDate(0, 0, -30).Format("2006-01-02")
	end := time.Now().Format("2006-01-02")
	var attendances []Attendance
	db.Where("student_id = ? AND date BETWEEN ? AND ?", student.ID, start, end).Order("date desc").Find(&attendances)

	// Grades
	var grades []Grade
	db.Where("student_id = ?", student.ID).Order("date desc").Limit(20).Find(&grades)

	// Attendance summary
	var presentCount int64
	db.Model(&Attendance{}).Where("student_id = ? AND date BETWEEN ? AND ? AND status = ?", student.ID, start, end, "present").Count(&presentCount)
	var totalCount int64
	db.Model(&Attendance{}).Where("student_id = ? AND date BETWEEN ? AND ?", student.ID, start, end).Count(&totalCount)
	rate := 0.0
	if totalCount > 0 {
		rate = float64(presentCount) / float64(totalCount) * 100
	}

	var avgScore float64
	db.Model(&Grade{}).Select("COALESCE(AVG(score), 0)").Where("student_id = ?", student.ID).Scan(&avgScore)

	c.JSON(200, gin.H{
		"student":         student,
		"attendances":     attendances,
		"grades":          grades,
		"present_count":   presentCount,
		"total_count":     totalCount,
		"attendance_rate": rate,
		"avg_score":       avgScore,
		"points":          student.Points,
	})
}

func getMyStudentProfile(c *gin.Context) {
	claims := getClaims(c)
	var student Student
	if err := db.Preload("Class").Where("user_id = ?", claims.UserID).First(&student).Error; err != nil {
		c.JSON(404, gin.H{"error": "profil tidak ditemukan"})
		return
	}
	c.JSON(200, student)
}

func getMyAttendance(c *gin.Context) {
	claims := getClaims(c)
	var student Student
	db.Where("user_id = ?", claims.UserID).First(&student)
	var records []Attendance
	db.Where("student_id = ?", student.ID).Order("date desc").Find(&records)
	c.JSON(200, records)
}

// ─── Change Password ──────────────────────────────────────────────────────────

// User ganti password sendiri (perlu password lama)
func handleChangePassword(c *gin.Context) {
	claims := getClaims(c)
	var body struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := c.BindJSON(&body); err != nil {
		c.JSON(400, gin.H{"error": "invalid payload"})
		return
	}
	if len(body.NewPassword) < 6 {
		c.JSON(400, gin.H{"error": "password baru minimal 6 karakter"})
		return
	}
	var user User
	if err := db.First(&user, claims.UserID).Error; err != nil {
		c.JSON(404, gin.H{"error": "user tidak ditemukan"})
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(body.OldPassword)); err != nil {
		c.JSON(401, gin.H{"error": "password lama salah"})
		return
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte(body.NewPassword), bcrypt.DefaultCost)
	db.Model(&user).Update("password_hash", string(hash))
	c.JSON(200, gin.H{"message": "password berhasil diubah"})
}

// Superadmin ganti password user lain (tanpa perlu password lama)
func handleAdminChangePassword(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var body struct {
		NewPassword string `json:"new_password"`
	}
	if err := c.BindJSON(&body); err != nil {
		c.JSON(400, gin.H{"error": "invalid payload"})
		return
	}
	if len(body.NewPassword) < 6 {
		c.JSON(400, gin.H{"error": "password minimal 6 karakter"})
		return
	}
	var user User
	if err := db.First(&user, id).Error; err != nil {
		c.JSON(404, gin.H{"error": "user tidak ditemukan"})
		return
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte(body.NewPassword), bcrypt.DefaultCost)
	db.Model(&user).Update("password_hash", string(hash))
	c.JSON(200, gin.H{"message": "password berhasil diubah"})
}

func getMyGrades(c *gin.Context) {
	claims := getClaims(c)
	var student Student
	db.Where("user_id = ?", claims.UserID).First(&student)
	var grades []Grade
	db.Where("student_id = ?", student.ID).Order("date desc").Find(&grades)
	c.JSON(200, grades)
}
