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

    toObject() {
        return { xss: this.#xss, sqli: this.#sqli };
    }

    static createEmpty() {
        return new ScanFlags({ xss: false, sqli: false });
    }
}

class UserAnswer {
    #pregunta_id;
    #respuestas_seleccionadas;
    #puntos_obtenidos;

    constructor(data = {}) {
        this.#pregunta_id = data.pregunta_id;
        this.#respuestas_seleccionadas = data.respuestas_seleccionadas || [];
        this.#puntos_obtenidos = data.puntos_obtenidos || 0;
    }

    get pregunta_id() { return this.#pregunta_id; }
    get respuestas_seleccionadas() { return this.#respuestas_seleccionadas; }
    get puntos_obtenidos() { return this.#puntos_obtenidos; }
    get numero_intentos() { return this.#respuestas_seleccionadas.length; }

    toObject() {
        return {
            pregunta_id: this.#pregunta_id,
            respuestas_seleccionadas: this.#respuestas_seleccionadas,
            puntos_obtenidos: this.#puntos_obtenidos
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
    UserAnswer,
    Score
};
