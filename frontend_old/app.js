const state = {
  mode: "instructor",
  token: "",
  email: "",
  password: "",
};

const output = document.getElementById("output");
const authState = document.getElementById("auth-state");

const modeButtons = {
  instructor: document.getElementById("mode-instructor"),
  student: document.getElementById("mode-student"),
};

function setMode(mode) {
  state.mode = mode;
  Object.entries(modeButtons).forEach(([key, button]) => {
    const active = key === mode;
    button.classList.toggle("active", active);
    button.setAttribute("aria-selected", active ? "true" : "false");
  });
  if (mode === "student") {
    setAuthState("Student mode: fallback auth", "warn");
  }
}

function setAuthState(text, kind = "") {
  authState.textContent = text;
  authState.classList.remove("ok", "warn");
  if (kind) authState.classList.add(kind);
}

function logBlock(title, payload) {
  const stamp = new Date().toLocaleTimeString();
  const text = `${stamp} | ${title}\n${JSON.stringify(payload, null, 2)}\n\n`;
  output.textContent = text + output.textContent;
}

function getCreds() {
  state.email = document.getElementById("email").value.trim();
  state.password = document.getElementById("password").value;
  return { email: state.email, password: state.password };
}

async function callApi(method, endpoint, body = null, useToken = true) {
  const headers = { "Content-Type": "application/json" };
  if (useToken && state.token) {
    headers.Authorization = `Bearer ${state.token}`;
  }

  const response = await fetch(endpoint, {
    method,
    headers,
    body: body ? JSON.stringify(body) : null,
  });
  const data = await response.json().catch(() => ({ detail: "No JSON body" }));
  logBlock(`${method} ${endpoint}`, { status: response.status, ok: response.ok, data });
  if (!response.ok) {
    throw new Error(data.detail || `HTTP ${response.status}`);
  }
  return data;
}

async function signIn() {
  const { email, password } = getCreds();
  if (!email || !password) {
    logBlock("Validation", { error: "Email and password are required." });
    return;
  }

  if (state.mode === "instructor") {
    const data = await callApi("POST", "/instructor/login", { email, password }, false);
    state.token = data.access_token;
    setAuthState(`Instructor signed in: ${data.email}`, "ok");
    return;
  }

  state.token = "";
  setAuthState(`Student ready: ${email}`, "ok");
  logBlock("Student Auth", {
    note: "Student endpoints use grading-script fallback in this build.",
    email,
  });
}

function signOut() {
  state.token = "";
  setAuthState("Not signed in");
}

function getInstructorCourseId() {
  return document.getElementById("course-id").value.trim();
}

function getActivityNo() {
  return Number(document.getElementById("activity-no").value);
}

async function loadCourses() {
  await callApi("GET", "/instructor/courses", null, true);
}

async function loadActivities() {
  const courseId = getInstructorCourseId();
  if (!courseId) return logBlock("Validation", { error: "course_id is required." });
  await callApi("GET", `/instructor/activities?course_id=${encodeURIComponent(courseId)}`, null, true);
}

async function startActivity() {
  const courseId = getInstructorCourseId();
  const activityNo = getActivityNo();
  if (!courseId || !activityNo) return logBlock("Validation", { error: "course_id and activity_no are required." });
  await callApi("POST", `/instructor/activity/start?course_id=${encodeURIComponent(courseId)}&activity_no=${activityNo}`, null, true);
}

async function endActivity() {
  const courseId = getInstructorCourseId();
  const activityNo = getActivityNo();
  if (!courseId || !activityNo) return logBlock("Validation", { error: "course_id and activity_no are required." });
  await callApi("POST", `/instructor/activity/end?course_id=${encodeURIComponent(courseId)}&activity_no=${activityNo}`, null, true);
}

async function resetActivity() {
  const courseId = getInstructorCourseId();
  const activityNo = getActivityNo();
  if (!courseId || !activityNo) return logBlock("Validation", { error: "course_id and activity_no are required." });
  await callApi("POST", `/instructor/activity/reset?course_id=${encodeURIComponent(courseId)}&activity_no=${activityNo}`, null, true);
}

function getStudentInputs() {
  const { email, password } = getCreds();
  const courseId = document.getElementById("student-course-id").value.trim();
  const activityNo = Number(document.getElementById("student-activity-no").value);
  const answer = document.getElementById("student-answer").value.trim();
  return { email, password, courseId, activityNo, answer };
}

async function fetchStudentActivity() {
  const { email, password, courseId, activityNo } = getStudentInputs();
  if (!email || !courseId || !activityNo) {
    return logBlock("Validation", { error: "email, course_id, activity_no are required." });
  }

  // Student endpoints allow grading-script fallback with email/password query args.
  const endpoint = `/student/activity?email=${encodeURIComponent(email)}&password=${encodeURIComponent(password)}&course_id=${encodeURIComponent(courseId)}&activity_no=${activityNo}`;
  await callApi("GET", endpoint, null, false);
}

async function submitStudentAnswer() {
  const { email, password, courseId, activityNo, answer } = getStudentInputs();
  if (!email || !courseId || !activityNo || !answer) {
    return logBlock("Validation", { error: "email, course_id, activity_no and answer are required." });
  }

  const body = { email, password, course_id: courseId, activity_no: activityNo, answer };
  await callApi("POST", "/student/answer", body, false);
}

function wireEvents() {
  modeButtons.instructor.addEventListener("click", () => setMode("instructor"));
  modeButtons.student.addEventListener("click", () => setMode("student"));

  document.getElementById("signin").addEventListener("click", () => signIn().catch((err) => logBlock("Error", { detail: err.message })));
  document.getElementById("signout").addEventListener("click", signOut);

  document.getElementById("load-courses").addEventListener("click", () => loadCourses().catch((err) => logBlock("Error", { detail: err.message })));
  document.getElementById("load-activities").addEventListener("click", () => loadActivities().catch((err) => logBlock("Error", { detail: err.message })));
  document.getElementById("start-activity").addEventListener("click", () => startActivity().catch((err) => logBlock("Error", { detail: err.message })));
  document.getElementById("end-activity").addEventListener("click", () => endActivity().catch((err) => logBlock("Error", { detail: err.message })));
  document.getElementById("reset-activity").addEventListener("click", () => resetActivity().catch((err) => logBlock("Error", { detail: err.message })));

  document.getElementById("fetch-activity").addEventListener("click", () => fetchStudentActivity().catch((err) => logBlock("Error", { detail: err.message })));
  document.getElementById("submit-answer").addEventListener("click", () => submitStudentAnswer().catch((err) => logBlock("Error", { detail: err.message })));

  document.getElementById("clear-log").addEventListener("click", () => {
    output.textContent = "";
  });
}

wireEvents();
setMode("instructor");
logBlock("Frontend Ready", {
  note: "Sign in as instructor for token-based calls; use student mode for tutoring flow endpoints.",
});
