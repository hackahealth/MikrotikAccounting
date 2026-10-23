"""محدوده دسترسی کاربران پنل به کارکنان (دفتر / واحد) و فیلترهای گزارش."""
from .db import Department, Office, User


def _ids(csv: str) -> set:
    return {int(x) for x in (csv or "").split(",") if x.strip().isdigit()}


def scope_of(me):
    """(office_ids, department_ids) of a scoped panel user; (None, None) = unrestricted.

    فقط دفتر: همه کارکنان آن دفتر(ها) — فقط واحد: همه کارکنان آن واحد(ها) در همه دفترها —
    هر دو: کارکنان آن واحد(ها) فقط در آن دفتر(ها).
    """
    if me is None:
        return set(), set()
    offices, depts = _ids(me.scope_offices), _ids(me.scope_departments)
    if not offices and not depts:
        if me.role == "unit_manager":       # a manager without a unit sees nobody
            return set(), set()
        return None, None
    return offices, depts


def is_scoped(me) -> bool:
    return scope_of(me)[0] is not None


def scope_query(q, me):
    """Restrict a User query to the panel user's scope."""
    offices, depts = scope_of(me)
    if offices is None:
        return q
    if not offices and not depts:
        return q.filter(User.id == -1)
    if offices:
        q = q.filter(User.office_id.in_(offices))
    if depts:
        q = q.filter(User.department_id.in_(depts))
    return q


def in_scope(me, user) -> bool:
    offices, depts = scope_of(me)
    if offices is None:
        return True
    if not offices and not depts:
        return False
    return (not offices or user.office_id in offices) and (not depts or user.department_id in depts)


def resolve_ids(db, me, group_id=None, office_id=None, department_id=None, user_id=None):
    """User ids for a report filter combined with the panel user's scope. None = all users."""
    if not (is_scoped(me) or group_id or office_id or department_id or user_id):
        return None
    q = scope_query(db.query(User.id), me)
    if user_id:
        q = q.filter(User.id == user_id)
    if group_id:
        q = q.filter(User.group_id == group_id)
    if office_id:
        q = q.filter(User.office_id == office_id)
    if department_id:
        q = q.filter(User.department_id == department_id)
    return [u for (u,) in q] or [-1]


def visible_offices(db, me):
    offices, depts = scope_of(me)
    q = db.query(Office).order_by(Office.name)
    if offices is None:
        return q.all()
    if offices:
        return q.filter(Office.id.in_(offices)).all()
    if depts:   # department-only scope: offices that contain those departments' staff
        oids = {o for (o,) in db.query(User.office_id).filter(User.department_id.in_(depts)) if o}
        return q.filter(Office.id.in_(oids or [-1])).all()
    return []


def visible_departments(db, me):
    offices, depts = scope_of(me)
    q = db.query(Department).order_by(Department.name)
    if offices is None:
        return q.all()
    if depts:
        return q.filter(Department.id.in_(depts)).all()
    if offices:
        dids = {d for (d,) in db.query(User.department_id).filter(User.office_id.in_(offices)) if d}
        return q.filter((Department.office_id.in_(offices)) | (Department.id.in_(dids or [-1]))).all()
    return []


def scope_label(db, me) -> str:
    offices, depts = scope_of(me)
    if offices is None:
        return ""
    parts = []
    if offices:
        parts.append("دفتر: " + ("، ".join(o.name for o in db.query(Office).filter(Office.id.in_(offices)))
                                 or "نامشخص در AD"))
    if depts:
        parts.append("واحد: " + ("، ".join(d.name for d in db.query(Department).filter(Department.id.in_(depts)))
                                 or "نامشخص در AD"))
    return " — ".join(parts) or "بدون محدوده (هیچ کارمندی)"
