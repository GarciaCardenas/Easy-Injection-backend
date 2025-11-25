// Value Objects for Scan model

class ScanFlags {
    #xss;
    #sqli;

    constructor(data = {}) {
        this.#xss = Boolean(data.xss);
        this.#sqli = Boolean(data.sqli);
    }

    get xss() { return this.#xss; }
    get sqli() { return this.#sqli; }

    hasAnyFlag() {
        return this.#xss || this.#sqli;
    }

    hasBothFlags() {
        return this.#xss && this.#sqli;
    }

    getEnabledFlags() {
        const flags = [];
        if (this.#xss) flags.push('XSS');
        if (this.#sqli) flags.push('SQLi');
        return flags;
    }

    toObject() {
        return { xss: this.#xss, sqli: this.#sqli };
    }

    static createEmpty() {
        return new ScanFlags({ xss: false, sqli: false });
    }

    static createXSSOnly() {
        return new ScanFlags({ xss: true, sqli: false });
    }

    static createSQLiOnly() {
        return new ScanFlags({ xss: false, sqli: true });
    }

    static createBoth() {
        return new ScanFlags({ xss: true, sqli: true });
    }
}

class Credentials {
    #usuario_login;
    #password_login;

    constructor(data = {}) {
        this.#usuario_login = data.usuario_login;
        this.#password_login = data.password_login;
    }

    get usuario_login() { return this.#usuario_login; }
    get password_login() { return this.#password_login; }

    hasCredentials() {
        return Boolean(this.#usuario_login && this.#password_login);
    }

    isValid() {
        return this.hasCredentials() && 
               this.#usuario_login.length > 0 && 
               this.#password_login.length > 0;
    }

    toObject() {
        return {
            usuario_login: this.#usuario_login,
            password_login: this.#password_login
        };
    }

    static createEmpty() {
        return new Credentials({ usuario_login: '', password_login: '' });
    }
}

class UserAnswer {
    #pregunta_id;
    #respuesta_seleccionada_id;
    #es_correcta;
    #puntos_obtenidos;
    #numero_intentos;

    constructor(data = {}) {
        this.#pregunta_id = data.pregunta_id;
        this.#respuesta_seleccionada_id = data.respuesta_seleccionada_id;
        this.#es_correcta = Boolean(data.es_correcta);
        this.#puntos_obtenidos = data.puntos_obtenidos || 0;
        this.#numero_intentos = data.numero_intentos || 1;
    }

    get pregunta_id() { return this.#pregunta_id; }
    get respuesta_seleccionada_id() { return this.#respuesta_seleccionada_id; }
    get es_correcta() { return this.#es_correcta; }
    get puntos_obtenidos() { return this.#puntos_obtenidos; }
    get numero_intentos() { return this.#numero_intentos; }

    isCorrect() {
        return this.#es_correcta === true;
    }

    toObject() {
        return {
            pregunta_id: this.#pregunta_id,
            respuesta_seleccionada_id: this.#respuesta_seleccionada_id,
            es_correcta: this.#es_correcta,
            puntos_obtenidos: this.#puntos_obtenidos,
            numero_intentos: this.#numero_intentos
        };
    }
}

class Score {
    #puntos_cuestionario;
    #total_puntos_cuestionario;
    #vulnerabilidades_encontradas;
    #puntuacion_final;
    #calificacion;

    constructor(data = {}) {
        this.#puntos_cuestionario = data.puntos_cuestionario || 0;
        this.#total_puntos_cuestionario = data.total_puntos_cuestionario || 0;
        this.#vulnerabilidades_encontradas = data.vulnerabilidades_encontradas || 0;
        this.#puntuacion_final = data.puntuacion_final || 0;
        this.#calificacion = data.calificacion || 'Regular';
    }

    get puntos_cuestionario() { return this.#puntos_cuestionario; }
    get total_puntos_cuestionario() { return this.#total_puntos_cuestionario; }
    get vulnerabilidades_encontradas() { return this.#vulnerabilidades_encontradas; }
    get puntuacion_final() { return this.#puntuacion_final; }
    get calificacion() { return this.#calificacion; }

    getQuizPercentage() {
        if (this.#total_puntos_cuestionario === 0) return 0;
        return Math.round((this.#puntos_cuestionario / this.#total_puntos_cuestionario) * 100);
    }

    calculateFinalScore() {
        // Componente de cuestionario (60% del total)
        let quizScore = 0;
        if (this.#total_puntos_cuestionario > 0) {
            // Calcular porcentaje obtenido del cuestionario
            const porcentajeCuestionario = this.#puntos_cuestionario / this.#total_puntos_cuestionario;
            // Escalar al 60%
            quizScore = porcentajeCuestionario * 60;
        }
        
        // Componente de vulnerabilidades (base 40 puntos)
        const penalizacionVulnerabilidades = this.#vulnerabilidades_encontradas * 5;
        let vulnerabilityScore = 40;
        let penalizacionExcedente = 0;
        
        if (penalizacionVulnerabilidades > 40) {
            // Si la penalización supera 40, el excedente se descuenta del cuestionario
            vulnerabilityScore = 0;
            penalizacionExcedente = penalizacionVulnerabilidades - 40;
        } else {
            vulnerabilityScore = 40 - penalizacionVulnerabilidades;
        }
        
        // Puntuación final con mínimo de 0
        this.#puntuacion_final = Math.max(0, Math.round(quizScore - penalizacionExcedente + vulnerabilityScore));
        
        if (this.#puntuacion_final >= 90) {
            this.#calificacion = 'Excelente';
        } else if (this.#puntuacion_final >= 75) {
            this.#calificacion = 'Bueno';
        } else if (this.#puntuacion_final >= 60) {
            this.#calificacion = 'Regular';
        } else if (this.#puntuacion_final >= 40) {
            this.#calificacion = 'Deficiente';
        } else {
            this.#calificacion = 'Crítico';
        }

        return this.#puntuacion_final;
    }

    addQuestionPoints(points) {
        this.#puntos_cuestionario += points;
    }

    setTotalQuestionPoints(total) {
        this.#total_puntos_cuestionario = total;
    }

    addVulnerability() {
        this.#vulnerabilidades_encontradas++;
    }

    isExcellent() {
        return this.#calificacion === 'Excelente';
    }

    isCritical() {
        return this.#calificacion === 'Crítico';
    }

    toObject() {
        return {
            puntos_cuestionario: this.#puntos_cuestionario,
            total_puntos_cuestionario: this.#total_puntos_cuestionario,
            vulnerabilidades_encontradas: this.#vulnerabilidades_encontradas,
            puntuacion_final: this.#puntuacion_final,
            calificacion: this.#calificacion
        };
    }

    static createEmpty() {
        return new Score({
            puntos_cuestionario: 0,
            total_puntos_cuestionario: 0,
            vulnerabilidades_encontradas: 0,
            puntuacion_final: 0,
            calificacion: 'Regular'
        });
    }
}

module.exports = {
    ScanFlags,
    Credentials,
    UserAnswer,
    Score
};
