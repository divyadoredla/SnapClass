import 'dotenv/config';
import express, { type Response } from 'express';
import path from 'path';
import { createServer as createViteServer } from 'vite';
import {
  type AuthenticatedRequest,
  clearSessionCookie,
  hashPassword,
  requireAuth,
  requireRole,
  setSessionCookie,
  signSessionToken,
  verifyPassword,
} from './server/auth.ts';
import {
  generateId,
  getDemoUserByRole,
  getStudentByUserId,
  getTeacherByUserId,
  getUserByEmail,
  readDb,
  writeDb,
} from './server/db.ts';
import {
  analyzeClassroomFaces,
  analyzeClassroomVoice,
  BiometricIntegrationError,
} from './server/gemini.ts';
import type {
  AnalyticsDashboardData,
  AttendanceMethod,
  AttendanceRecordItem,
  AttendanceSessionSummary,
  AttendanceStatus,
  AuthUser,
  StudentDashboardData,
  StudentRosterItem,
  SubjectSummary,
} from './src/types/snapclass.ts';

const app = express();
const PORT = 3000;

app.use(express.json({ limit: '25mb' }));
app.use((_, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'same-origin');
  next();
});

function buildAuthUserPayload(userId: string): AuthUser | null {
  const db = readDb();
  const user = db.users.find((u) => u.id === userId);
  if (!user) return null;

  const base: AuthUser = {
    id: user.id,
    email: user.email,
    name: user.name,
    role: user.role,
    avatarUrl: user.avatarUrl,
  };

  if (user.role === 'student') {
    const stu = db.students.find((s) => s.userId === user.id);
    if (stu) {
      base.studentProfile = {
        id: stu.id,
        rollNumber: stu.rollNumber,
        studentCode: stu.studentCode,
        batch: stu.batch,
        academicYear: stu.academicYear || '2026–2027',
        department: stu.department,
        phone: stu.phone,
      };
    }
  } else {
    const tch = db.teachers.find((t) => t.userId === user.id);
    if (tch) {
      base.teacherProfile = {
        id: tch.id,
        employeeCode: tch.employeeCode,
        department: tch.department,
        institution: tch.institution || 'SnapClass Institute of Technology',
        title: tch.title,
      };
    }
  }

  return base;
}

function isValidEmail(email: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function getIsoWeekKey(dateStr: string): string {
  const dt = new Date(`${dateStr}T00:00:00Z`);
  const day = dt.getUTCDay();
  const diff = dt.getUTCDate() - day + (day === 0 ? -6 : 1);
  const monday = new Date(dt);
  monday.setUTCDate(diff);
  return `Wk ${monday.toISOString().slice(5, 10)}`;
}

function getMonthKey(dateStr: string): string {
  const dt = new Date(`${dateStr}T00:00:00Z`);
  return dt.toLocaleString('en-US', { month: 'short', year: 'numeric', timeZone: 'UTC' });
}

app.get('/api/health', (_req, res) => {
  res.json({
    ok: true,
    geminiConfigured: Boolean(process.env.GEMINI_API_KEY?.trim()),
  });
});

// ==================== AUTH ROUTES ====================

app.post('/api/auth/register', (req, res) => {
  const {
    name,
    email,
    password,
    role,
    rollNumber,
    batch,
    academicYear,
    department,
    phone,
    employeeCode,
    institution,
    title,
  } = req.body ?? {};

  if (typeof name !== 'string' || name.trim().length < 2) {
    res.status(400).json({ error: 'Please enter a full name (at least 2 characters).' });
    return;
  }
  if (typeof email !== 'string' || !isValidEmail(email.trim())) {
    res.status(400).json({ error: 'Please enter a valid institutional email address.' });
    return;
  }
  if (typeof password !== 'string' || password.length < 8) {
    res.status(400).json({ error: 'Password must be at least 8 characters long.' });
    return;
  }
  if (role !== 'student' && role !== 'teacher') {
    res.status(400).json({ error: 'Account role must be student or teacher.' });
    return;
  }

  const normalizedEmail = email.trim().toLowerCase();
  if (getUserByEmail(normalizedEmail)) {
    res.status(409).json({ error: 'An account with this institutional email already exists.' });
    return;
  }

  const db = readDb();

  if (role === 'student') {
    if (typeof rollNumber !== 'string' || !rollNumber.trim()) {
      res.status(400).json({ error: 'Student roll number is required.' });
      return;
    }
    const cleanRoll = rollNumber.trim().toUpperCase();
    if (db.students.some((s) => s.rollNumber.toUpperCase() === cleanRoll)) {
      res.status(409).json({
        error: `A student with roll number "${cleanRoll}" is already registered.`,
      });
      return;
    }

    const { hash, salt } = hashPassword(password);
    const now = new Date().toISOString();
    const userId = generateId('usr');

    db.users.push({
      id: userId,
      email: normalizedEmail,
      name: name.trim(),
      role: 'student',
      passwordHash: hash,
      salt,
      createdAt: now,
    });

    db.students.push({
      id: generateId('stu'),
      userId,
      rollNumber: cleanRoll,
      studentCode: `SC-${new Date().getFullYear()}-${cleanRoll.slice(-4)}`,
      batch: typeof batch === 'string' && batch.trim() ? batch.trim() : 'CSE-A',
      academicYear:
        typeof academicYear === 'string' && academicYear.trim()
          ? academicYear.trim()
          : '2026–2027',
      department:
        typeof department === 'string' && department.trim()
          ? department.trim()
          : 'Computer Science & AI',
      phone: typeof phone === 'string' ? phone.trim() : '',
      createdAt: now,
    });

    writeDb(db);
    const token = signSessionToken(userId, 'student');
    setSessionCookie(res, token);
    res.status(201).json({ token, user: buildAuthUserPayload(userId) });
    return;
  }

  // Teacher registration
  if (typeof employeeCode !== 'string' || !employeeCode.trim()) {
    res.status(400).json({ error: 'Faculty ID is required for teacher registration.' });
    return;
  }
  const cleanFacultyId = employeeCode.trim().toUpperCase();
  if (db.teachers.some((t) => t.employeeCode.toUpperCase() === cleanFacultyId)) {
    res.status(409).json({
      error: `A teacher with Faculty ID "${cleanFacultyId}" is already registered.`,
    });
    return;
  }

  const { hash, salt } = hashPassword(password);
  const now = new Date().toISOString();
  const userId = generateId('usr');

  db.users.push({
    id: userId,
    email: normalizedEmail,
    name: name.trim(),
    role: 'teacher',
    passwordHash: hash,
    salt,
    createdAt: now,
  });

  db.teachers.push({
    id: generateId('tch'),
    userId,
    employeeCode: cleanFacultyId,
    department:
      typeof department === 'string' && department.trim()
        ? department.trim()
        : 'Computer Science & AI',
    institution:
      typeof institution === 'string' && institution.trim()
        ? institution.trim()
        : 'SnapClass Institute of Technology',
    title: typeof title === 'string' && title.trim() ? title.trim() : 'Assistant Professor',
    createdAt: now,
  });

  writeDb(db);
  const token = signSessionToken(userId, 'teacher');
  setSessionCookie(res, token);
  res.status(201).json({ token, user: buildAuthUserPayload(userId) });
});

app.post('/api/auth/login', (req, res) => {
  const { email, password, role } = req.body ?? {};
  if (typeof email !== 'string' || typeof password !== 'string') {
    res.status(400).json({ error: 'Email and password are required.' });
    return;
  }

  const user = getUserByEmail(email);
  if (!user || !verifyPassword(password, user.passwordHash, user.salt)) {
    res.status(401).json({ error: 'Invalid institutional email or password.' });
    return;
  }

  if (role && user.role !== role) {
    res.status(403).json({
      error: `This email belongs to a ${user.role} account. Please sign in through the ${user.role} portal.`,
    });
    return;
  }

  const token = signSessionToken(user.id, user.role);
  setSessionCookie(res, token);
  res.json({
    token,
    user: buildAuthUserPayload(user.id),
  });
});

app.post('/api/auth/demo', (req, res) => {
  const { role } = req.body ?? {};
  if (role !== 'student' && role !== 'teacher') {
    res.status(400).json({ error: 'Specify role: student or teacher.' });
    return;
  }
  const demoUser = getDemoUserByRole(role);
  if (!demoUser) {
    res.status(404).json({ error: 'Demo profile not available.' });
    return;
  }
  const token = signSessionToken(demoUser.id, demoUser.role);
  setSessionCookie(res, token);
  res.json({
    token,
    user: buildAuthUserPayload(demoUser.id),
  });
});

app.post('/api/auth/logout', (_req, res) => {
  clearSessionCookie(res);
  res.json({ ok: true });
});

app.get('/api/auth/me', requireAuth, (req: AuthenticatedRequest, res) => {
  res.json({ user: buildAuthUserPayload(req.authUser!.id) });
});

app.post('/api/auth/change-password', requireAuth, (req: AuthenticatedRequest, res) => {
  const { currentPassword, newPassword } = req.body ?? {};
  if (typeof newPassword !== 'string' || newPassword.length < 8) {
    res.status(400).json({ error: 'New password must be at least 8 characters long.' });
    return;
  }

  const db = readDb();
  const user = db.users.find((u) => u.id === req.authUser!.id);
  if (!user) {
    res.status(404).json({ error: 'Account not found.' });
    return;
  }

  if (!user.isDemo) {
    if (typeof currentPassword !== 'string' || !verifyPassword(currentPassword, user.passwordHash, user.salt)) {
      res.status(401).json({ error: 'Current password is incorrect.' });
      return;
    }
  }

  const { hash, salt } = hashPassword(newPassword);
  user.passwordHash = hash;
  user.salt = salt;
  user.isDemo = false;
  writeDb(db);
  res.json({ ok: true, message: 'Password updated securely.' });
});

// ==================== STUDENT ROUTES ====================

app.get('/api/student/dashboard', requireAuth, requireRole('student'), (req: AuthenticatedRequest, res) => {
  const db = readDb();
  const user = db.users.find((u) => u.id === req.authUser!.id)!;
  const student = getStudentByUserId(user.id);
  if (!student) {
    res.status(404).json({ error: 'Student profile not found.' });
    return;
  }

  const myEnrollments = db.enrollments.filter((e) => e.studentId === student.id);
  const enrolledSubjectIds = new Set(myEnrollments.map((e) => e.subjectId));
  const mySubjects = db.subjects.filter((s) => enrolledSubjectIds.has(s.id));
  const myRecords = db.attendanceRecords
    .filter((r) => r.studentId === student.id)
    .sort((a, b) => b.date.localeCompare(a.date));

  const totalClasses = myRecords.length;
  const classesAttended = myRecords.filter((r) => r.status === 'present' || r.status === 'late').length;
  const classesMissed = myRecords.filter((r) => r.status === 'absent').length;
  const classesLate = myRecords.filter((r) => r.status === 'late').length;
  const attendancePercentage =
    totalClasses > 0 ? Math.round((classesAttended / totalClasses) * 1000) / 10 : 0;

  const faceProfile = db.faceProfiles.find((fp) => fp.studentId === student.id);
  const voiceProfile = db.voiceProfiles.find((vp) => vp.studentId === student.id);

  const subjectStats = mySubjects.map((sub) => {
    const teacher = db.teachers.find((t) => t.id === sub.teacherId);
    const teacherUser = teacher ? db.users.find((u) => u.id === teacher.userId) : undefined;
    const subRecords = myRecords.filter((r) => r.subjectId === sub.id);
    const subAttended = subRecords.filter((r) => r.status === 'present' || r.status === 'late').length;
    return {
      id: sub.id,
      code: sub.code,
      name: sub.name,
      teacherName: teacherUser?.name || 'Instructor',
      schedule: sub.schedule,
      department: sub.department,
      semester: sub.semester,
      totalClasses: subRecords.length,
      attended: subAttended,
      percentage:
        subRecords.length > 0 ? Math.round((subAttended / subRecords.length) * 1000) / 10 : 0,
    };
  });

  // Derive upcoming classes from enrolled subject schedules
  const dayNames = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
  const todayIdx = new Date().getDay();
  const upcomingClasses: StudentDashboardData['upcomingClasses'] = [];
  for (const sub of subjectStats) {
    if (!sub.schedule || sub.schedule === 'TBD') continue;
    let dayLabel = 'Scheduled';
    for (let offset = 0; offset < 7; offset++) {
      const candidateDay = dayNames[(todayIdx + offset) % 7];
      if (sub.schedule.includes(candidateDay)) {
        dayLabel = offset === 0 ? 'Today' : offset === 1 ? 'Tomorrow' : candidateDay;
        break;
      }
    }
    upcomingClasses.push({
      subjectId: sub.id,
      code: sub.code,
      name: sub.name,
      schedule: sub.schedule,
      teacherName: sub.teacherName,
      dayLabel,
    });
  }

  const history: AttendanceRecordItem[] = myRecords.map((r) => {
    const sub = db.subjects.find((s) => s.id === r.subjectId);
    return {
      id: r.id,
      sessionId: r.sessionId,
      subjectId: r.subjectId,
      subjectCode: sub?.code || 'N/A',
      subjectName: sub?.name || 'Unknown Subject',
      studentId: student.id,
      studentName: user.name,
      rollNumber: student.rollNumber,
      date: r.date,
      status: r.status,
      method: r.method,
      confidence: r.confidence,
      verificationNote: r.verificationNote,
      verifiedByTeacher: r.verifiedByTeacher,
    };
  });

  const byDate = new Map<string, { attended: number; total: number }>();
  const byWeek = new Map<string, { attended: number; total: number }>();
  const byMonth = new Map<string, { label: string; attended: number; total: number }>();

  for (const r of myRecords) {
    const dEntry = byDate.get(r.date) || { attended: 0, total: 0 };
    dEntry.total += 1;
    if (r.status === 'present' || r.status === 'late') dEntry.attended += 1;
    byDate.set(r.date, dEntry);

    const wk = getIsoWeekKey(r.date);
    const wEntry = byWeek.get(wk) || { attended: 0, total: 0 };
    wEntry.total += 1;
    if (r.status === 'present' || r.status === 'late') wEntry.attended += 1;
    byWeek.set(wk, wEntry);

    const monthIso = r.date.slice(0, 7);
    const mEntry = byMonth.get(monthIso) || {
      label: getMonthKey(r.date),
      attended: 0,
      total: 0,
    };
    mEntry.total += 1;
    if (r.status === 'present' || r.status === 'late') mEntry.attended += 1;
    byMonth.set(monthIso, mEntry);
  }

  const trend = Array.from(byDate.entries())
    .sort((a, b) => a[0].localeCompare(b[0]))
    .map(([date, val]) => ({
      date,
      attended: val.attended,
      total: val.total,
      percentage: Math.round((val.attended / val.total) * 100),
    }));

  const weeklyTrend = Array.from(byWeek.entries())
    .sort((a, b) => a[0].localeCompare(b[0]))
    .map(([week, val]) => ({
      week,
      attended: val.attended,
      total: val.total,
      rate: Math.round((val.attended / val.total) * 100),
    }));

  const monthlyTrend = Array.from(byMonth.entries())
    .sort((a, b) => a[0].localeCompare(b[0]))
    .map(([, val]) => ({
      month: val.label,
      attended: val.attended,
      total: val.total,
      rate: Math.round((val.attended / val.total) * 100),
    }));

  const payload: StudentDashboardData = {
    student: {
      id: student.id,
      name: user.name,
      email: user.email,
      avatarUrl: faceProfile?.imageDataUrl || user.avatarUrl,
      rollNumber: student.rollNumber,
      studentCode: student.studentCode,
      batch: student.batch,
      academicYear: student.academicYear || '2026–2027',
      department: student.department,
      phone: student.phone,
    },
    overview: {
      totalClasses,
      classesAttended,
      classesMissed,
      classesLate,
      attendancePercentage,
    },
    biometrics: {
      faceEnrolled: Boolean(faceProfile?.enrolled),
      faceUpdatedAt: faceProfile?.updatedAt || null,
      facePreviewUrl: faceProfile?.imageDataUrl || null,
      voiceEnrolled: Boolean(voiceProfile?.enrolled),
      voiceUpdatedAt: voiceProfile?.updatedAt || null,
      voicePassphrase: voiceProfile?.passphrase || null,
      voiceDurationSec: voiceProfile?.durationSec || null,
      voiceVadSegments: voiceProfile?.vadSegmentsCount || null,
    },
    subjects: subjectStats,
    upcomingClasses,
    history,
    trend,
    weeklyTrend,
    monthlyTrend,
  };

  res.json(payload);
});

app.patch('/api/student/profile', requireAuth, requireRole('student'), (req: AuthenticatedRequest, res) => {
  const { name, batch, academicYear, department, phone } = req.body ?? {};
  const db = readDb();
  const user = db.users.find((u) => u.id === req.authUser!.id);
  const student = db.students.find((s) => s.userId === req.authUser!.id);
  if (!user || !student) {
    res.status(404).json({ error: 'Student account not found.' });
    return;
  }

  if (typeof name === 'string' && name.trim().length >= 2) {
    user.name = name.trim();
  }
  if (typeof batch === 'string' && batch.trim()) {
    student.batch = batch.trim();
  }
  if (typeof academicYear === 'string' && academicYear.trim()) {
    student.academicYear = academicYear.trim();
  }
  if (typeof department === 'string' && department.trim()) {
    student.department = department.trim();
  }
  if (typeof phone === 'string') {
    student.phone = phone.trim();
  }

  writeDb(db);
  res.json({ user: buildAuthUserPayload(user.id) });
});

app.post('/api/student/join-class', requireAuth, requireRole('student'), (req: AuthenticatedRequest, res) => {
  const { joinCode } = req.body ?? {};
  if (typeof joinCode !== 'string' || !joinCode.trim()) {
    res.status(400).json({ error: 'Please enter a valid class join code.' });
    return;
  }

  const db = readDb();
  const student = getStudentByUserId(req.authUser!.id);
  if (!student) {
    res.status(404).json({ error: 'Student record not found.' });
    return;
  }

  const normalizedCode = joinCode.trim().toUpperCase();
  const subject = db.subjects.find((s) => s.joinCode.toUpperCase() === normalizedCode);
  if (!subject) {
    res.status(404).json({ error: `No class found with join code "${normalizedCode}".` });
    return;
  }

  const already = db.enrollments.find(
    (e) => e.subjectId === subject.id && e.studentId === student.id
  );
  if (already) {
    res.status(409).json({ error: `You are already enrolled in ${subject.code} — ${subject.name}.` });
    return;
  }

  db.enrollments.push({
    id: generateId('enr'),
    subjectId: subject.id,
    studentId: student.id,
    enrolledAt: new Date().toISOString(),
  });
  writeDb(db);

  res.status(201).json({
    message: `Successfully enrolled in ${subject.code}: ${subject.name}`,
    subject: { id: subject.id, code: subject.code, name: subject.name },
  });
});

app.post('/api/student/biometrics/face', requireAuth, requireRole('student'), (req: AuthenticatedRequest, res) => {
  const { imageDataUrl } = req.body ?? {};
  if (typeof imageDataUrl !== 'string' || !/^data:image\/(jpeg|png|webp);base64,/.test(imageDataUrl)) {
    res.status(400).json({ error: 'Please provide a valid JPEG, PNG, or WebP face image.' });
    return;
  }
  const db = readDb();
  const student = getStudentByUserId(req.authUser!.id);
  const user = db.users.find((u) => u.id === req.authUser!.id);
  if (!student || !user) {
    res.status(404).json({ error: 'Student profile not found.' });
    return;
  }

  const now = new Date().toISOString();
  const existing = db.faceProfiles.find((fp) => fp.studentId === student.id);
  if (existing) {
    existing.enrolled = true;
    existing.imageDataUrl = imageDataUrl;
    existing.updatedAt = now;
  } else {
    db.faceProfiles.push({
      id: generateId('fp'),
      studentId: student.id,
      enrolled: true,
      imageDataUrl,
      updatedAt: now,
    });
  }
  user.avatarUrl = imageDataUrl;
  writeDb(db);
  res.json({ enrolled: true, updatedAt: now });
});

app.post('/api/student/biometrics/voice', requireAuth, requireRole('student'), (req: AuthenticatedRequest, res) => {
  const { audioDataUrl, passphrase, durationSec, vadSegmentsCount } = req.body ?? {};
  if (typeof audioDataUrl !== 'string' || !/^data:audio\/[a-z0-9.+-]+(?:;[^,]*)?;base64,/i.test(audioDataUrl)) {
    res.status(400).json({ error: 'Please provide a valid recorded or uploaded audio sample.' });
    return;
  }
  const db = readDb();
  const student = getStudentByUserId(req.authUser!.id);
  if (!student) {
    res.status(404).json({ error: 'Student profile not found.' });
    return;
  }

  const mimeMatch = /^data:(audio\/[a-z0-9.+-]+)/i.exec(audioDataUrl);
  const mimeType = mimeMatch ? mimeMatch[1].toLowerCase() : 'audio/webm';
  const now = new Date().toISOString();
  const cleanPassphrase =
    typeof passphrase === 'string' && passphrase.trim()
      ? passphrase.trim()
      : `Present, ${req.authUser!.name}, Roll ${student.rollNumber}`;

  const existing = db.voiceProfiles.find((vp) => vp.studentId === student.id);
  if (existing) {
    existing.enrolled = true;
    existing.audioDataUrl = audioDataUrl;
    existing.mimeType = mimeType;
    existing.passphrase = cleanPassphrase;
    existing.durationSec = Number(durationSec) || 3;
    existing.vadSegmentsCount = Number(vadSegmentsCount) || 1;
    existing.updatedAt = now;
  } else {
    db.voiceProfiles.push({
      id: generateId('vp'),
      studentId: student.id,
      enrolled: true,
      audioDataUrl,
      mimeType,
      passphrase: cleanPassphrase,
      durationSec: Number(durationSec) || 3,
      vadSegmentsCount: Number(vadSegmentsCount) || 1,
      updatedAt: now,
    });
  }

  writeDb(db);
  res.json({ enrolled: true, updatedAt: now });
});

// ==================== TEACHER ROUTES ====================

function getTeacherSubjectSummaries(teacherId: string): SubjectSummary[] {
  const db = readDb();
  const teacher = db.teachers.find((t) => t.id === teacherId);
  const teacherUser = teacher ? db.users.find((u) => u.id === teacher.userId) : undefined;
  const subjects = db.subjects.filter((s) => s.teacherId === teacherId);
  const todayStr = new Date().toISOString().slice(0, 10);

  return subjects.map((sub) => {
    const enrolledIds = db.enrollments
      .filter((e) => e.subjectId === sub.id)
      .map((e) => e.studentId);
    const enrolledSet = new Set(enrolledIds);
    const faceEnrolledCount = db.faceProfiles.filter(
      (fp) => fp.enrolled && enrolledSet.has(fp.studentId)
    ).length;
    const voiceEnrolledCount = db.voiceProfiles.filter(
      (vp) => vp.enrolled && enrolledSet.has(vp.studentId)
    ).length;
    const sessions = db.attendanceSessions.filter((ses) => ses.subjectId === sub.id);
    const records = db.attendanceRecords.filter((rec) => rec.subjectId === sub.id);
    const attended = records.filter((r) => r.status === 'present' || r.status === 'late').length;
    const avg = records.length > 0 ? Math.round((attended / records.length) * 1000) / 10 : 0;
    const markedToday = sessions.some((ses) => ses.date === todayStr);

    return {
      id: sub.id,
      code: sub.code,
      name: sub.name,
      department: sub.department,
      semester: sub.semester,
      schedule: sub.schedule,
      joinCode: sub.joinCode,
      teacherName: teacherUser?.name || 'Instructor',
      enrolledCount: enrolledIds.length,
      faceEnrolledCount,
      voiceEnrolledCount,
      sessionsCount: sessions.length,
      averageAttendance: avg,
      markedToday,
    };
  });
}

app.get('/api/teacher/dashboard', requireAuth, requireRole('teacher'), (req: AuthenticatedRequest, res) => {
  const db = readDb();
  const teacher = getTeacherByUserId(req.authUser!.id);
  if (!teacher) {
    res.status(404).json({ error: 'Teacher profile not found.' });
    return;
  }

  const subjects = getTeacherSubjectSummaries(teacher.id);
  const subjectIds = new Set(subjects.map((s) => s.id));

  const uniqueStudents = new Set(
    db.enrollments.filter((e) => subjectIds.has(e.subjectId)).map((e) => e.studentId)
  );
  const sessions = db.attendanceSessions
    .filter((ses) => subjectIds.has(ses.subjectId))
    .sort((a, b) => b.date.localeCompare(a.date) || b.createdAt.localeCompare(a.createdAt));
  const records = db.attendanceRecords.filter((rec) => subjectIds.has(rec.subjectId));
  const attended = records.filter((r) => r.status === 'present' || r.status === 'late').length;
  const avgAttendance = records.length > 0 ? Math.round((attended / records.length) * 1000) / 10 : 0;

  const recentSessions: AttendanceSessionSummary[] = sessions.slice(0, 12).map((ses) => {
    const sub = subjects.find((s) => s.id === ses.subjectId);
    const sesRecords = records.filter((r) => r.sessionId === ses.id);
    return {
      id: ses.id,
      subjectId: ses.subjectId,
      subjectCode: sub?.code || 'N/A',
      subjectName: sub?.name || 'Unknown Subject',
      date: ses.date,
      method: ses.method,
      notes: ses.notes,
      presentCount: sesRecords.filter((r) => r.status === 'present').length,
      absentCount: sesRecords.filter((r) => r.status === 'absent').length,
      lateCount: sesRecords.filter((r) => r.status === 'late').length,
      totalStudents: sesRecords.length,
      createdAt: ses.createdAt,
    };
  });

  res.json({
    overview: {
      totalStudents: uniqueStudents.size,
      totalSubjects: subjects.length,
      classesConducted: sessions.length,
      averageAttendance: avgAttendance,
      pendingTodayCount: subjects.filter((s) => !s.markedToday).length,
    },
    subjects,
    recentSessions,
  });
});

app.patch('/api/teacher/profile', requireAuth, requireRole('teacher'), (req: AuthenticatedRequest, res) => {
  const { name, department, institution, title } = req.body ?? {};
  const db = readDb();
  const user = db.users.find((u) => u.id === req.authUser!.id);
  const teacher = db.teachers.find((t) => t.userId === req.authUser!.id);
  if (!user || !teacher) {
    res.status(404).json({ error: 'Teacher account not found.' });
    return;
  }

  if (typeof name === 'string' && name.trim().length >= 2) user.name = name.trim();
  if (typeof department === 'string' && department.trim()) teacher.department = department.trim();
  if (typeof institution === 'string' && institution.trim()) teacher.institution = institution.trim();
  if (typeof title === 'string' && title.trim()) teacher.title = title.trim();

  writeDb(db);
  res.json({ user: buildAuthUserPayload(user.id) });
});

app.get('/api/teacher/students', requireAuth, requireRole('teacher'), (req: AuthenticatedRequest, res) => {
  const db = readDb();
  const teacher = getTeacherByUserId(req.authUser!.id);
  if (!teacher) {
    res.status(404).json({ error: 'Teacher profile not found.' });
    return;
  }

  const teacherSubjects = db.subjects.filter((s) => s.teacherId === teacher.id);
  const teacherSubjectMap = new Map(teacherSubjects.map((s) => [s.id, s.code]));
  const teacherSubjectIds = new Set(teacherSubjects.map((s) => s.id));

  const studentSubjectsMap = new Map<string, string[]>();
  for (const enr of db.enrollments) {
    if (!teacherSubjectIds.has(enr.subjectId)) continue;
    const list = studentSubjectsMap.get(enr.studentId) || [];
    const code = teacherSubjectMap.get(enr.subjectId);
    if (code) list.push(code);
    studentSubjectsMap.set(enr.studentId, list);
  }

  const students: StudentRosterItem[] = [];
  for (const [stuId, subjectCodes] of studentSubjectsMap.entries()) {
    const stu = db.students.find((s) => s.id === stuId);
    if (!stu) continue;
    const usr = db.users.find((u) => u.id === stu.userId);
    if (!usr) continue;
    const face = db.faceProfiles.find((fp) => fp.studentId === stu.id);
    const voice = db.voiceProfiles.find((vp) => vp.studentId === stu.id);

    students.push({
      studentId: stu.id,
      name: usr.name,
      email: usr.email,
      rollNumber: stu.rollNumber,
      studentCode: stu.studentCode,
      batch: stu.batch,
      academicYear: stu.academicYear || '2026–2027',
      department: stu.department,
      avatarUrl: face?.imageDataUrl || usr.avatarUrl,
      faceEnrolled: Boolean(face?.enrolled),
      faceUpdatedAt: face?.updatedAt || null,
      voiceEnrolled: Boolean(voice?.enrolled),
      voiceUpdatedAt: voice?.updatedAt || null,
      voicePassphrase: voice?.passphrase || null,
      enrolledSubjectCodes: subjectCodes,
    });
  }

  students.sort((a, b) => a.rollNumber.localeCompare(b.rollNumber));
  res.json({ students });
});

app.get('/api/teacher/sessions', requireAuth, requireRole('teacher'), (req: AuthenticatedRequest, res) => {
  const db = readDb();
  const teacher = getTeacherByUserId(req.authUser!.id);
  if (!teacher) {
    res.status(404).json({ error: 'Teacher profile not found.' });
    return;
  }

  const subjects = db.subjects.filter((s) => s.teacherId === teacher.id);
  const subjectIds = new Set(subjects.map((s) => s.id));
  const sessions = db.attendanceSessions
    .filter((s) => subjectIds.has(s.subjectId))
    .sort((a, b) => b.date.localeCompare(a.date) || b.createdAt.localeCompare(a.createdAt));

  const sessionSummaries = sessions.map((ses) => {
    const sub = subjects.find((s) => s.id === ses.subjectId);
    const sesRecords = db.attendanceRecords
      .filter((r) => r.sessionId === ses.id)
      .map((r) => {
        const stu = db.students.find((s) => s.id === r.studentId);
        const usr = stu ? db.users.find((u) => u.id === stu.userId) : undefined;
        return {
          id: r.id,
          sessionId: r.sessionId,
          subjectId: r.subjectId,
          subjectCode: sub?.code || 'N/A',
          subjectName: sub?.name || 'Subject',
          studentId: r.studentId,
          studentName: usr?.name || 'Student',
          rollNumber: stu?.rollNumber || 'N/A',
          batch: stu?.batch || 'N/A',
          date: r.date,
          status: r.status,
          method: r.method,
          confidence: r.confidence,
          verificationNote: r.verificationNote,
          verifiedByTeacher: r.verifiedByTeacher,
        };
      });

    return {
      id: ses.id,
      subjectId: ses.subjectId,
      subjectCode: sub?.code || 'N/A',
      subjectName: sub?.name || 'Subject',
      date: ses.date,
      method: ses.method,
      notes: ses.notes,
      presentCount: sesRecords.filter((r) => r.status === 'present').length,
      absentCount: sesRecords.filter((r) => r.status === 'absent').length,
      lateCount: sesRecords.filter((r) => r.status === 'late').length,
      totalStudents: sesRecords.length,
      createdAt: ses.createdAt,
      records: sesRecords,
    };
  });

  res.json({ sessions: sessionSummaries });
});

app.post('/api/teacher/subjects', requireAuth, requireRole('teacher'), (req: AuthenticatedRequest, res) => {
  const { code, name, department, semester, schedule } = req.body ?? {};
  if (typeof code !== 'string' || !code.trim() || typeof name !== 'string' || !name.trim()) {
    res.status(400).json({ error: 'Subject code and subject name are required.' });
    return;
  }

  const db = readDb();
  const teacher = getTeacherByUserId(req.authUser!.id);
  if (!teacher) {
    res.status(404).json({ error: 'Teacher profile not found.' });
    return;
  }

  const cleanCode = code.trim().toUpperCase();
  const randomSuffix = Math.random().toString(36).slice(2, 6).toUpperCase();
  const joinCode = `SNAP-${cleanCode.replace(/[^A-Z0-9]/g, '').slice(0, 6)}-${randomSuffix}`;

  const newSub = {
    id: generateId('sub'),
    teacherId: teacher.id,
    code: cleanCode,
    name: name.trim(),
    department:
      typeof department === 'string' && department.trim()
        ? department.trim()
        : teacher.department,
    semester: typeof semester === 'string' && semester.trim() ? semester.trim() : 'Current Semester',
    schedule: typeof schedule === 'string' && schedule.trim() ? schedule.trim() : 'TBD',
    joinCode,
    createdAt: new Date().toISOString(),
  };

  db.subjects.push(newSub);
  writeDb(db);

  res.status(201).json({ subject: newSub });
});

app.post('/api/teacher/subjects/:id/regenerate-code', requireAuth, requireRole('teacher'), (req: AuthenticatedRequest, res) => {
  const db = readDb();
  const teacher = getTeacherByUserId(req.authUser!.id);
  const subject = db.subjects.find((s) => s.id === req.params.id);
  if (!teacher || !subject || subject.teacherId !== teacher.id) {
    res.status(404).json({ error: 'Subject not found or unauthorized.' });
    return;
  }

  const randomSuffix = Math.random().toString(36).slice(2, 6).toUpperCase();
  subject.joinCode = `SNAP-${subject.code.replace(/[^A-Z0-9]/g, '').slice(0, 6)}-${randomSuffix}`;
  writeDb(db);
  res.json({ joinCode: subject.joinCode });
});

app.get('/api/teacher/subjects/:id/roster', requireAuth, requireRole('teacher'), (req: AuthenticatedRequest, res) => {
  const db = readDb();
  const teacher = getTeacherByUserId(req.authUser!.id);
  const subject = db.subjects.find((s) => s.id === req.params.id);
  if (!teacher || !subject || subject.teacherId !== teacher.id) {
    res.status(404).json({ error: 'Subject not found or access denied.' });
    return;
  }

  const enrollments = db.enrollments.filter((e) => e.subjectId === subject.id);
  const roster: StudentRosterItem[] = [];

  for (const enr of enrollments) {
    const stu = db.students.find((s) => s.id === enr.studentId);
    if (!stu) continue;
    const u = db.users.find((usr) => usr.id === stu.userId);
    if (!u) continue;
    const face = db.faceProfiles.find((fp) => fp.studentId === stu.id);
    const voice = db.voiceProfiles.find((vp) => vp.studentId === stu.id);

    roster.push({
      studentId: stu.id,
      name: u.name,
      email: u.email,
      rollNumber: stu.rollNumber,
      studentCode: stu.studentCode,
      batch: stu.batch,
      academicYear: stu.academicYear || '2026–2027',
      department: stu.department,
      avatarUrl: face?.imageDataUrl || u.avatarUrl,
      faceEnrolled: Boolean(face?.enrolled),
      faceUpdatedAt: face?.updatedAt || null,
      voiceEnrolled: Boolean(voice?.enrolled),
      voiceUpdatedAt: voice?.updatedAt || null,
      voicePassphrase: voice?.passphrase || null,
    });
  }

  roster.sort((a, b) => a.rollNumber.localeCompare(b.rollNumber));
  res.json({ subject, roster });
});

app.post('/api/teacher/students/:studentId/biometrics/face', requireAuth, requireRole('teacher'), (req: AuthenticatedRequest, res) => {
  const { imageDataUrl } = req.body ?? {};
  if (typeof imageDataUrl !== 'string' || !/^data:image\/(jpeg|png|webp);base64,/.test(imageDataUrl)) {
    res.status(400).json({ error: 'Invalid face image format.' });
    return;
  }
  const db = readDb();
  const teacher = getTeacherByUserId(req.authUser!.id);
  const student = db.students.find((s) => s.id === req.params.studentId);
  if (!teacher || !student) {
    res.status(404).json({ error: 'Student not found.' });
    return;
  }
  const teacherSubjectIds = new Set(db.subjects.filter((s) => s.teacherId === teacher.id).map((s) => s.id));
  const isEnrolledInMyClass = db.enrollments.some(
    (e) => e.studentId === student.id && teacherSubjectIds.has(e.subjectId)
  );
  if (!isEnrolledInMyClass) {
    res.status(403).json({ error: 'Student is not enrolled in your subjects.' });
    return;
  }

  const now = new Date().toISOString();
  const existing = db.faceProfiles.find((fp) => fp.studentId === student.id);
  if (existing) {
    existing.enrolled = true;
    existing.imageDataUrl = imageDataUrl;
    existing.updatedAt = now;
  } else {
    db.faceProfiles.push({
      id: generateId('fp'),
      studentId: student.id,
      enrolled: true,
      imageDataUrl,
      updatedAt: now,
    });
  }
  const studentUser = db.users.find((u) => u.id === student.userId);
  if (studentUser) studentUser.avatarUrl = imageDataUrl;
  writeDb(db);
  res.json({ enrolled: true, updatedAt: now });
});

app.post('/api/teacher/students/:studentId/biometrics/voice', requireAuth, requireRole('teacher'), (req: AuthenticatedRequest, res) => {
  const { audioDataUrl, passphrase, durationSec, vadSegmentsCount } = req.body ?? {};
  if (typeof audioDataUrl !== 'string' || !/^data:audio\/[a-z0-9.+-]+(?:;[^,]*)?;base64,/i.test(audioDataUrl)) {
    res.status(400).json({ error: 'Invalid audio sample format.' });
    return;
  }
  const db = readDb();
  const teacher = getTeacherByUserId(req.authUser!.id);
  const student = db.students.find((s) => s.id === req.params.studentId);
  if (!teacher || !student) {
    res.status(404).json({ error: 'Student not found.' });
    return;
  }
  const teacherSubjectIds = new Set(db.subjects.filter((s) => s.teacherId === teacher.id).map((s) => s.id));
  const isEnrolledInMyClass = db.enrollments.some(
    (e) => e.studentId === student.id && teacherSubjectIds.has(e.subjectId)
  );
  if (!isEnrolledInMyClass) {
    res.status(403).json({ error: 'Student is not enrolled in your subjects.' });
    return;
  }

  const studentUser = db.users.find((u) => u.id === student.userId);
  const mimeMatch = /^data:(audio\/[a-z0-9.+-]+)/i.exec(audioDataUrl);
  const mimeType = mimeMatch ? mimeMatch[1].toLowerCase() : 'audio/webm';
  const now = new Date().toISOString();
  const cleanPassphrase =
    typeof passphrase === 'string' && passphrase.trim()
      ? passphrase.trim()
      : `Present, ${studentUser?.name || student.rollNumber}`;

  const existing = db.voiceProfiles.find((vp) => vp.studentId === student.id);
  if (existing) {
    existing.enrolled = true;
    existing.audioDataUrl = audioDataUrl;
    existing.mimeType = mimeType;
    existing.passphrase = cleanPassphrase;
    existing.durationSec = Number(durationSec) || 3;
    existing.vadSegmentsCount = Number(vadSegmentsCount) || 1;
    existing.updatedAt = now;
  } else {
    db.voiceProfiles.push({
      id: generateId('vp'),
      studentId: student.id,
      enrolled: true,
      audioDataUrl,
      mimeType,
      passphrase: cleanPassphrase,
      durationSec: Number(durationSec) || 3,
      vadSegmentsCount: Number(vadSegmentsCount) || 1,
      updatedAt: now,
    });
  }
  writeDb(db);
  res.json({ enrolled: true, updatedAt: now });
});

// ==================== BIOMETRIC RECOGNITION & ATTENDANCE ====================

function handleBiometricError(err: unknown, res: Response): void {
  if (err instanceof BiometricIntegrationError) {
    res.status(err.status).json({ error: err.message, code: err.code });
    return;
  }
  console.error('Biometric endpoint error:', err);
  res.status(500).json({ error: 'Unexpected server error during biometric analysis.' });
}

app.post('/api/attendance/recognize-face', requireAuth, requireRole('teacher'), async (req: AuthenticatedRequest, res) => {
  const { subjectId, imageDataUrl } = req.body ?? {};
  if (typeof subjectId !== 'string' || typeof imageDataUrl !== 'string') {
    res.status(400).json({ error: 'Subject ID and classroom image are required.' });
    return;
  }

  const db = readDb();
  const teacher = getTeacherByUserId(req.authUser!.id);
  const subject = db.subjects.find((s) => s.id === subjectId);
  if (!teacher || !subject || subject.teacherId !== teacher.id) {
    res.status(404).json({ error: 'Subject not found or unauthorized.' });
    return;
  }

  const enrolledIds = db.enrollments.filter((e) => e.subjectId === subject.id).map((e) => e.studentId);
  const candidates = [];
  for (const stuId of enrolledIds) {
    const fp = db.faceProfiles.find((f) => f.studentId === stuId && f.enrolled);
    const stu = db.students.find((s) => s.id === stuId);
    const usr = stu ? db.users.find((u) => u.id === stu.userId) : undefined;
    if (fp && stu && usr) {
      candidates.push({
        studentId: stu.id,
        name: usr.name,
        rollNumber: stu.rollNumber,
        imageDataUrl: fp.imageDataUrl,
      });
    }
  }

  try {
    const result = await analyzeClassroomFaces(imageDataUrl, candidates, enrolledIds.length);
    res.json(result);
  } catch (err) {
    handleBiometricError(err, res);
  }
});

app.post('/api/attendance/recognize-voice', requireAuth, requireRole('teacher'), async (req: AuthenticatedRequest, res) => {
  const { subjectId, audioDataUrl } = req.body ?? {};
  if (typeof subjectId !== 'string' || typeof audioDataUrl !== 'string') {
    res.status(400).json({ error: 'Subject ID and classroom audio recording are required.' });
    return;
  }

  const db = readDb();
  const teacher = getTeacherByUserId(req.authUser!.id);
  const subject = db.subjects.find((s) => s.id === subjectId);
  if (!teacher || !subject || subject.teacherId !== teacher.id) {
    res.status(404).json({ error: 'Subject not found or unauthorized.' });
    return;
  }

  const enrolledIds = db.enrollments.filter((e) => e.subjectId === subject.id).map((e) => e.studentId);
  const candidates = [];
  for (const stuId of enrolledIds) {
    const vp = db.voiceProfiles.find((v) => v.studentId === stuId && v.enrolled);
    const stu = db.students.find((s) => s.id === stuId);
    const usr = stu ? db.users.find((u) => u.id === stu.userId) : undefined;
    if (vp && stu && usr) {
      candidates.push({
        studentId: stu.id,
        name: usr.name,
        rollNumber: stu.rollNumber,
        passphrase: vp.passphrase,
        audioDataUrl: vp.audioDataUrl,
      });
    }
  }

  try {
    const result = await analyzeClassroomVoice(audioDataUrl, candidates, enrolledIds.length);
    res.json(result);
  } catch (err) {
    handleBiometricError(err, res);
  }
});

app.post('/api/attendance/sessions', requireAuth, requireRole('teacher'), (req: AuthenticatedRequest, res) => {
  const { subjectId, date, method, notes, records, overwrite } = req.body ?? {};
  if (
    typeof subjectId !== 'string' ||
    typeof date !== 'string' ||
    !/^\d{4}-\d{2}-\d{2}$/.test(date) ||
    !Array.isArray(records)
  ) {
    res.status(400).json({ error: 'Valid subjectId, YYYY-MM-DD date, and records array are required.' });
    return;
  }

  const validMethod: AttendanceMethod =
    method === 'face' || method === 'voice' || method === 'manual' ? method : 'manual';

  const db = readDb();
  const teacher = getTeacherByUserId(req.authUser!.id);
  const subject = db.subjects.find((s) => s.id === subjectId);
  if (!teacher || !subject || subject.teacherId !== teacher.id) {
    res.status(404).json({ error: 'Subject not found or unauthorized.' });
    return;
  }

  const existingSession = db.attendanceSessions.find(
    (s) => s.subjectId === subjectId && s.date === date
  );
  if (existingSession && !overwrite) {
    res.status(409).json({
      error: `Attendance for ${subject.code} on ${date} has already been recorded. Confirm overwrite to replace this session.`,
      code: 'DUPLICATE_SESSION',
    });
    return;
  }

  if (existingSession && overwrite) {
    db.attendanceSessions = db.attendanceSessions.filter((s) => s.id !== existingSession.id);
    db.attendanceRecords = db.attendanceRecords.filter((r) => r.sessionId !== existingSession.id);
  }

  const enrolledSet = new Set(
    db.enrollments.filter((e) => e.subjectId === subjectId).map((e) => e.studentId)
  );

  const sessionId = generateId('ses');
  const now = new Date().toISOString();
  db.attendanceSessions.push({
    id: sessionId,
    subjectId,
    teacherId: teacher.id,
    date,
    method: validMethod,
    notes: typeof notes === 'string' ? notes.trim() : '',
    createdAt: now,
  });

  const seenStudentIds = new Set<string>();
  for (const item of records) {
    if (!item || typeof item.studentId !== 'string') continue;
    if (!enrolledSet.has(item.studentId) || seenStudentIds.has(item.studentId)) continue;
    seenStudentIds.add(item.studentId);

    const status: AttendanceStatus =
      item.status === 'present' || item.status === 'absent' || item.status === 'late'
        ? item.status
        : 'absent';

    db.attendanceRecords.push({
      id: generateId('rec'),
      sessionId,
      subjectId,
      studentId: item.studentId,
      date,
      status,
      method: validMethod,
      confidence:
        typeof item.confidence === 'number' ? Math.max(0, Math.min(99, Math.round(item.confidence))) : null,
      verificationNote:
        typeof item.verificationNote === 'string' && item.verificationNote.trim()
          ? item.verificationNote.trim()
          : 'Verified by instructor',
      verifiedByTeacher: true,
      createdAt: now,
    });
  }

  writeDb(db);
  res.status(201).json({
    sessionId,
    savedCount: seenStudentIds.size,
  });
});

// ==================== ANALYTICS ROUTE ====================

app.get('/api/analytics', requireAuth, requireRole('teacher'), (req: AuthenticatedRequest, res) => {
  const db = readDb();
  const teacher = getTeacherByUserId(req.authUser!.id);
  if (!teacher) {
    res.status(404).json({ error: 'Teacher profile not found.' });
    return;
  }

  const subjectFilter = typeof req.query.subjectId === 'string' ? req.query.subjectId : 'all';
  const batchFilter = typeof req.query.batch === 'string' ? req.query.batch : 'all';
  const startDate = typeof req.query.startDate === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(req.query.startDate)
    ? req.query.startDate
    : '';
  const endDate = typeof req.query.endDate === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(req.query.endDate)
    ? req.query.endDate
    : '';

  const mySubjects = db.subjects.filter((s) => s.teacherId === teacher.id);
  const allowedSubjectIds = new Set(mySubjects.map((s) => s.id));

  const targetSubjectIds =
    subjectFilter !== 'all' && allowedSubjectIds.has(subjectFilter)
      ? new Set([subjectFilter])
      : allowedSubjectIds;

  // Collect all batches across teacher's enrolled students
  const allEnrolledIds = new Set(
    db.enrollments.filter((e) => allowedSubjectIds.has(e.subjectId)).map((e) => e.studentId)
  );
  const availableBatches = Array.from(
    new Set(
      db.students
        .filter((s) => allEnrolledIds.has(s.id))
        .map((s) => s.batch)
        .filter(Boolean)
    )
  ).sort();

  const matchingBatchStudentIds =
    batchFilter !== 'all'
      ? new Set(db.students.filter((s) => s.batch === batchFilter).map((s) => s.id))
      : null;

  const rawRecords = db.attendanceRecords.filter((r) => {
    if (!targetSubjectIds.has(r.subjectId)) return false;
    if (matchingBatchStudentIds && !matchingBatchStudentIds.has(r.studentId)) return false;
    if (startDate && r.date < startDate) return false;
    if (endDate && r.date > endDate) return false;
    return true;
  });

  const activeSessionIds = new Set(rawRecords.map((r) => r.sessionId));
  const sessions = db.attendanceSessions.filter(
    (s) =>
      targetSubjectIds.has(s.subjectId) &&
      (!startDate || s.date >= startDate) &&
      (!endDate || s.date <= endDate) &&
      (batchFilter === 'all' || activeSessionIds.has(s.id))
  );

  const records: AttendanceRecordItem[] = rawRecords
    .map((r) => {
      const sub = mySubjects.find((s) => s.id === r.subjectId);
      const stu = db.students.find((st) => st.id === r.studentId);
      const usr = stu ? db.users.find((u) => u.id === stu.userId) : undefined;
      return {
        id: r.id,
        sessionId: r.sessionId,
        subjectId: r.subjectId,
        subjectCode: sub?.code || 'N/A',
        subjectName: sub?.name || 'Subject',
        studentId: r.studentId,
        studentName: usr?.name || 'Student',
        rollNumber: stu?.rollNumber || 'N/A',
        batch: stu?.batch || 'N/A',
        date: r.date,
        status: r.status,
        method: r.method,
        confidence: r.confidence,
        verificationNote: r.verificationNote,
        verifiedByTeacher: r.verifiedByTeacher,
      };
    })
    .sort((a, b) => b.date.localeCompare(a.date));

  const presentTotal = rawRecords.filter((r) => r.status === 'present').length;
  const lateTotal = rawRecords.filter((r) => r.status === 'late').length;
  const absentTotal = rawRecords.filter((r) => r.status === 'absent').length;
  const avgRate =
    rawRecords.length > 0
      ? Math.round(((presentTotal + lateTotal) / rawRecords.length) * 1000) / 10
      : 0;

  // Daily trend
  const dailyMap = new Map<string, { present: number; absent: number; late: number }>();
  for (const r of rawRecords) {
    const entry = dailyMap.get(r.date) || { present: 0, absent: 0, late: 0 };
    entry[r.status] += 1;
    dailyMap.set(r.date, entry);
  }
  const dailyTrend = Array.from(dailyMap.entries())
    .sort((a, b) => a[0].localeCompare(b[0]))
    .map(([date, counts]) => {
      const total = counts.present + counts.absent + counts.late;
      return {
        date,
        present: counts.present,
        absent: counts.absent,
        late: counts.late,
        rate: total > 0 ? Math.round(((counts.present + counts.late) / total) * 100) : 0,
      };
    });

  // Weekly trend
  const weeklyMap = new Map<string, { attended: number; total: number; sessions: Set<string> }>();
  const monthlyMap = new Map<
    string,
    { label: string; attended: number; total: number; sessions: Set<string> }
  >();

  for (const r of rawRecords) {
    const weekKey = getIsoWeekKey(r.date);
    const wEntry = weeklyMap.get(weekKey) || { attended: 0, total: 0, sessions: new Set() };
    wEntry.total += 1;
    if (r.status === 'present' || r.status === 'late') wEntry.attended += 1;
    wEntry.sessions.add(r.sessionId);
    weeklyMap.set(weekKey, wEntry);

    const monthIso = r.date.slice(0, 7);
    const mEntry = monthlyMap.get(monthIso) || {
      label: getMonthKey(r.date),
      attended: 0,
      total: 0,
      sessions: new Set(),
    };
    mEntry.total += 1;
    if (r.status === 'present' || r.status === 'late') mEntry.attended += 1;
    mEntry.sessions.add(r.sessionId);
    monthlyMap.set(monthIso, mEntry);
  }

  const weeklyTrend = Array.from(weeklyMap.entries())
    .sort((a, b) => a[0].localeCompare(b[0]))
    .map(([week, val]) => ({
      week,
      rate: val.total > 0 ? Math.round((val.attended / val.total) * 100) : 0,
      sessions: val.sessions.size,
    }));

  const monthlyTrend = Array.from(monthlyMap.entries())
    .sort((a, b) => a[0].localeCompare(b[0]))
    .map(([, val]) => ({
      month: val.label,
      rate: val.total > 0 ? Math.round((val.attended / val.total) * 100) : 0,
      sessions: val.sessions.size,
    }));

  // Subject comparison
  const subjectComparison = mySubjects.map((sub) => {
    const subRecords = db.attendanceRecords.filter((r) => {
      if (r.subjectId !== sub.id) return false;
      if (matchingBatchStudentIds && !matchingBatchStudentIds.has(r.studentId)) return false;
      if (startDate && r.date < startDate) return false;
      if (endDate && r.date > endDate) return false;
      return true;
    });
    const subSessionIds = new Set(subRecords.map((r) => r.sessionId));
    const subAttended = subRecords.filter((r) => r.status === 'present' || r.status === 'late').length;
    return {
      subjectId: sub.id,
      code: sub.code,
      name: sub.name,
      rate: subRecords.length > 0 ? Math.round((subAttended / subRecords.length) * 1000) / 10 : 0,
      sessions: subSessionIds.size,
    };
  });

  // Student breakdown
  const enrolledStudentIds = new Set(
    db.enrollments
      .filter((e) => targetSubjectIds.has(e.subjectId))
      .map((e) => e.studentId)
      .filter((id) => !matchingBatchStudentIds || matchingBatchStudentIds.has(id))
  );

  const studentBreakdown = Array.from(enrolledStudentIds)
    .map((stuId) => {
      const stu = db.students.find((s) => s.id === stuId);
      const usr = stu ? db.users.find((u) => u.id === stu.userId) : undefined;
      const stuRecords = rawRecords.filter((r) => r.studentId === stuId);
      const stuAttended = stuRecords.filter(
        (r) => r.status === 'present' || r.status === 'late'
      ).length;
      const stuMissed = stuRecords.filter((r) => r.status === 'absent').length;
      const rate =
        stuRecords.length > 0 ? Math.round((stuAttended / stuRecords.length) * 1000) / 10 : 0;
      return {
        studentId: stuId,
        name: usr?.name || 'Student',
        rollNumber: stu?.rollNumber || 'N/A',
        batch: stu?.batch || 'N/A',
        totalClasses: stuRecords.length,
        attended: stuAttended,
        missed: stuMissed,
        rate,
      };
    })
    .sort((a, b) => a.rollNumber.localeCompare(b.rollNumber));

  const studentDistribution = [
    {
      bucket: '90–100%',
      count: studentBreakdown.filter((s) => s.totalClasses > 0 && s.rate >= 90).length,
    },
    {
      bucket: '75–89%',
      count: studentBreakdown.filter((s) => s.totalClasses > 0 && s.rate >= 75 && s.rate < 90).length,
    },
    {
      bucket: '60–74%',
      count: studentBreakdown.filter((s) => s.totalClasses > 0 && s.rate >= 60 && s.rate < 75).length,
    },
    {
      bucket: 'Below 60%',
      count: studentBreakdown.filter((s) => s.totalClasses > 0 && s.rate < 60).length,
    },
  ];

  const atRiskStudentsCount = studentBreakdown.filter(
    (s) => s.totalClasses > 0 && s.rate < 75
  ).length;

  const payload: AnalyticsDashboardData = {
    kpis: {
      totalSessions: sessions.length,
      totalRecords: rawRecords.length,
      averageAttendance: avgRate,
      atRiskStudentsCount,
    },
    availableBatches,
    dailyTrend,
    weeklyTrend,
    monthlyTrend,
    subjectComparison,
    statusDistribution: [
      { name: 'Present', value: presentTotal },
      { name: 'Late', value: lateTotal },
      { name: 'Absent', value: absentTotal },
    ],
    studentDistribution,
    studentBreakdown,
    records,
  };

  res.json(payload);
});

// ==================== SERVER STARTUP ====================

async function startServer(): Promise<void> {
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.resolve(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.resolve(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`SnapClass server listening on http://localhost:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('Failed to start SnapClass server:', err);
  process.exit(1);
});
