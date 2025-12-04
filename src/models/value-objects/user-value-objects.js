// Value Objects for User model

class Profile {
    #nivel_actual;
    #avatarId;
    #puntos_totales;

    constructor(data = {}) {
        this.#nivel_actual = data.nivel_actual || 1;
        this.#avatarId = data.avatarId || 'avatar1';
        this.#puntos_totales = data.puntos_totales || 0;
    }

    get nivel_actual() { return this.#nivel_actual; }
    get avatarId() { return this.#avatarId; }
    get puntos_totales() { return this.#puntos_totales; }

    levelUp() {
        this.#nivel_actual++;
        return this.#nivel_actual;
    }

    updateLevel(level) {
        this.#nivel_actual = level;
        return this.#nivel_actual;
    }

    addPoints(points) {
        this.#puntos_totales += points;
        return this.#puntos_totales;
    }

    getTotalPoints() {
        return this.#puntos_totales;
    }

    setAvatar(avatarId) {
        const validAvatars = ['avatar1', 'avatar2', 'avatar3', 'avatar4', 'avatar5', 'avatar6'];
        if (!validAvatars.includes(avatarId)) {
            throw new Error('Avatar ID inválido');
        }
        this.#avatarId = avatarId;
    }

    getLevel() {
        return this.#nivel_actual;
    }

    getAvatarId() {
        return this.#avatarId;
    }

    toObject() {
        return {
            nivel_actual: this.#nivel_actual,
            avatarId: this.#avatarId,
            puntos_totales: this.#puntos_totales
        };
    }

    static createDefault() {
        return new Profile({ nivel_actual: 1, avatarId: 'avatar1', puntos_totales: 0 });
    }

    static createEmpty() {
        return new Profile({ nivel_actual: 1, avatarId: 'avatar1', puntos_totales: 0 });
    }
}

class Notification {
    #titulo;
    #mensaje;
    #leida;
    #fecha_creacion;

    constructor(data = {}) {
        this.#titulo = data.titulo;
        this.#mensaje = data.mensaje;
        this.#leida = data.leida !== undefined ? data.leida : false;
        this.#fecha_creacion = data.fecha_creacion || new Date();
    }

    get titulo() { return this.#titulo; }
    get mensaje() { return this.#mensaje; }
    get leida() { return this.#leida; }
    get fecha_creacion() { return this.#fecha_creacion; }

    markAsRead() {
        this.#leida = true;
    }

    markAsUnread() {
        this.#leida = false;
    }

    isRead() {
        return this.#leida === true;
    }

    isUnread() {
        return this.#leida === false;
    }

    getAge() {
        return Math.floor((new Date() - this.#fecha_creacion) / (1000 * 60 * 60 * 24));
    }

    isRecent() {
        return this.getAge() <= 7;
    }

    toObject() {
        return {
            titulo: this.#titulo,
            mensaje: this.#mensaje,
            leida: this.#leida,
            fecha_creacion: this.#fecha_creacion
        };
    }

    static create(titulo, mensaje) {
        return new Notification({ titulo, mensaje, leida: false });
    }
}

module.exports = {
    Profile,
    Notification
};
