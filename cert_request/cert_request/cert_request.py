"""TO-DO: Write a description of what this XBlock is."""

import pkg_resources

from xblock.core import XBlock
from xblock.fields import Scope, String, Integer
from xblock.fragment import Fragment
from mako.template import Template

from django.contrib.auth.models import User
from certificates import api as certs_api
from opaque_keys.edx.keys import CourseKey
from courseware.courses import get_course_by_id
from courseware.views import is_course_passed
from courseware.model_data import FieldDataCache, ScoresClient
from functools import partial
#from courseware.grades import field_data_cache_for_grading
from util.module_utils import yield_dynamic_descriptor_descendants
from courseware.access import has_access
from xmodule.graders import Score
from xmodule import graders
from courseware.courses import (
    get_courses,
    get_course,
    get_course_by_id,
    get_permission_for_course_about,
    get_studio_url,
    get_course_overview_with_access,
    get_course_with_access,
    sort_by_announcement,
    sort_by_start_date,
    UserNotEnrolled
)
from courseware import grades
def weighted_score(raw_correct, raw_total, weight):
    """Return a tuple that represents the weighted (correct, total) score."""
    # If there is no weighting, or weighting can't be applied, return input.
    if weight is None or raw_total == 0:
        return (raw_correct, raw_total)
    return (float(raw_correct) * weight / raw_total, float(weight))

def get_score(user, problem_descriptor, module_creator, scores_client, submissions_scores_cache, max_scores_cache):
    """
    Return the score for a user on a problem, as a tuple (correct, total).
    e.g. (5,7) if you got 5 out of 7 points.
    If this problem doesn't have a score, or we couldn't load it, returns (None,
    None).
    user: a Student object
    problem_descriptor: an XModuleDescriptor
    scores_client: an initialized ScoresClient
    module_creator: a function that takes a descriptor, and returns the corresponding XModule for this user.
           Can return None if user doesn't have access, or if something else went wrong.
    submissions_scores_cache: A dict of location names to (earned, possible) point tuples.
           If an entry is found in this cache, it takes precedence.
    max_scores_cache: a MaxScoresCache
    """
    submissions_scores_cache = submissions_scores_cache or {}

    if not user.is_authenticated():
        return (None, None)

    location_url = problem_descriptor.location.to_deprecated_string()
    if location_url in submissions_scores_cache:
        return submissions_scores_cache[location_url]

    # some problems have state that is updated independently of interaction
    # with the LMS, so they need to always be scored. (E.g. combinedopenended ORA1.)
    if problem_descriptor.always_recalculate_grades:
        problem = module_creator(problem_descriptor)
        if problem is None:
            return (None, None)
        score = problem.get_score()
        if score is not None:
            return (score['score'], score['total'])
        else:
            return (None, None)

    if not problem_descriptor.has_score:
        # These are not problems, and do not have a score
        return (None, None)

    # Check the score that comes from the ScoresClient (out of CSM).
    # If an entry exists and has a total associated with it, we trust that
    # value. This is important for cases where a student might have seen an
    # older version of the problem -- they're still graded on what was possible
    # when they tried the problem, not what it's worth now.
    score = scores_client.get(problem_descriptor.location)
    cached_max_score = max_scores_cache.get(problem_descriptor.location)
    if score and score.total is not None:
        # We have a valid score, just use it.
        correct = score.correct if score.correct is not None else 0.0
        total = score.total
    elif cached_max_score is not None and settings.FEATURES.get("ENABLE_MAX_SCORE_CACHE"):
        # We don't have a valid score entry but we know from our cache what the
        # max possible score is, so they've earned 0.0 / cached_max_score
        correct = 0.0
        total = cached_max_score
    else:
        # This means we don't have a valid score entry and we don't have a
        # cached_max_score on hand. We know they've earned 0.0 points on this,
        # but we need to instantiate the module (i.e. load student state) in
        # order to find out how much it was worth.
        problem = module_creator(problem_descriptor)
        if problem is None:
            return (None, None)

        correct = 0.0
        total = problem.max_score()

        # Problem may be an error module (if something in the problem builder failed)
        # In which case total might be None
        if total is None:
            return (None, None)
        else:
            # add location to the max score cache
            max_scores_cache.set(problem_descriptor.location, total)

    return weighted_score(correct, total, problem_descriptor.weight)





class MaxScoresCache(object):

	def __init__(self, cache_prefix):
	        self.cache_prefix = cache_prefix
        	self._max_scores_cache = {}
        	self._max_scores_updates = {}

    	@classmethod
    	def create_for_course(cls, course):
		if course.subtree_edited_on is None:
            		# check for subtree_edited_on because old XML courses doesn't have this attribute
            		cache_key = u"{}".format(course.id)
        	else:
            		cache_key = u"{}.{}".format(course.id, course.subtree_edited_on.isoformat())
        	return cls(cache_key)

	def push_to_remote(self):
        	"""
        	Update the remote cache
       	        """
        	if self._max_scores_updates:
            		cache.set_many(
                		{
                    			self._remote_cache_key(key): value
                    			for key, value in self._max_scores_updates.items()
                		},
                		60 * 60 * 24  # 1 day
            		)

    	def _remote_cache_key(self, location):
        	"""Convert a location to a remote cache key (add our prefixing)."""
        	return u"grades.MaxScores.{}___{}".format(self.cache_prefix, unicode(location))

    	def _local_cache_key(self, remote_key):
        	"""Convert a remote cache key to a local cache key (i.e. location str)."""
        	return remote_key.split(u"___", 1)[1]

    	def num_cached_from_remote(self):
        	"""How many items did we pull down from the remote cache?"""
        	return len(self._max_scores_cache)

    	def num_cached_updates(self):
        	"""How many local updates are we waiting to push to the remote cache?"""
        	return len(self._max_scores_updates)

    	def set(self, location, max_score):
        	"""
        	Adds a max score to the max_score_cache
		"""
		loc_str = unicode(location)
       		if self._max_scores_cache.get(loc_str) != max_score:
            		self._max_scores_updates[loc_str] = max_score

    	def get(self, location):
        	"""
       		 Retrieve a max score from the cache
        	"""
       		loc_str = unicode(location)
        	max_score = self._max_scores_updates.get(loc_str)
        	if max_score is None:
            		max_score = self._max_scores_cache.get(loc_str)
        	return max_score


class CertRequestXBlock(XBlock):
    
    display_name = String(
        default='On Demand Certificate', scope=Scope.settings,
        help="This name appears in the horizontal navigation at the top of "
             "the page.",
    )
    
    def resource_string(self, path):
        """Handy helper for getting resources from our kit."""
        data = pkg_resources.resource_string(__name__, path)
        return data.decode("utf8")
    
    def render_template(self, template_path, context={}):
        """
        Evaluate a template by resource path, applying the provided context
        """
        template_str = self.resource_string(template_path)
        template = Template(template_str)
        return template.render(**context)


    # TO-DO: change this view to display your data your own way.
    def student_view(self, context=None):
        """
        Redirect to author view when viewing in studio
        """
        if getattr(self.runtime, 'is_author_mode', False):
            return self.author_view()

        context = {}
        certificate_status = self.get_cert_status()
        context.update(certificate_status)

        #html = self.resource_string("static/html/cert_request.html")
        frag = Fragment()
        frag.add_content(
            self.render_template(
                'static/html/cert_request.html', context
            )
        )
        #frag.add_css(self.resource_string("static/css/cert_request.css"))
        #frag.add_javascript(self.resource_string("static/js/src/cert_request.js"))
        #frag.initialize_js('CertRequestXBlock')
        return frag


    def studio_view(self, context):
        """
        Create a fragment used to display the edit view in the Studio.
        """
        html_str = self.resource_string("static/html/cert_request_edit.html")
        display_name = self.display_name or ''
        frag = Fragment(unicode(html_str).format(display_name=display_name))
        frag.add_javascript(self.resource_string("static/js/src/cert_request_edit.js"))
        frag.initialize_js('CertEditBlock')

        return frag

    def author_view(self, context=None):
        html_str = self.resource_string("static/html/cert_request_studio.html")
        display_name = self.display_name or ''
        frag = Fragment(unicode(html_str).format(display_name=display_name))
        return frag

    @XBlock.json_handler
    def studio_submit(self, data, suffix=''):
        """
        Called when submitting the form in Studio.
        """
        self.display_name = data.get('display_name')

        return {'result': 'success'}


	
    def descriptor_affects_grading(self,block_types_affecting_grading, descriptor):
    	"""
    	Returns True if the descriptor could have any impact on grading, else False.
    	Something might be a scored item if it is capable of storing a score
    	(has_score=True). We also have to include anything that can have children,
    	since those children might have scores. We can avoid things like Videos,
    			which have state but cannot ever impact someone's grade.
    	"""
    	return descriptor.location.block_type in block_types_affecting_grading


    def field_data_cache_for_grading(self,course, user):
    	"""
    	Given a CourseDescriptor and User, create the FieldDataCache for grading.
    	This will generate a FieldDataCache that only loads state for those things
    	that might possibly affect the grading process, and will ignore things like
    	Videos.
    	"""
    	descriptor_filter = partial(self.descriptor_affects_grading, course.block_types_affecting_grading)
    	return FieldDataCache.cache_for_descriptor_descendents(
        	course.id,
        	user,
        	course,
        	depth=None,
        	descriptor_filter=descriptor_filter
    	)


    


    def get_cert_status(self):
        student_id = self.scope_ids.user_id
        course_id = str(self.xmodule_runtime.course_id)
        course_key = CourseKey.from_string(course_id)
        student = User.objects.prefetch_related("groups").get(id=student_id)
	course = get_course_with_access(student, 'load', course_key, depth=None, check_if_enrolled=True)

	field_data_cache = self.field_data_cache_for_grading(course, student)
	scores_client = ScoresClient.from_field_data_cache(field_data_cache)
	
        show_generate_cert_btn = certs_api.cert_generation_enabled(course_key)

	from django.conf import settings
	grading_context = course.grading_context
	
	totaled_scores = {}
	keep_raw_scores	= None
	from submissions import api as sub_api
	from student.models import anonymous_id_for_user
	submissions_scores = sub_api.get_scores(
            course.id.to_deprecated_string(), anonymous_id_for_user(student, course.id)
        )
	max_scores_cache = MaxScoresCache.create_for_course(course)	
	for section_format, sections in grading_context['graded_sections'].iteritems():
        	format_scores = []
        	for section in sections:
            		section_descriptor = section['section_descriptor']
            		section_name = section_descriptor.display_name_with_default

			should_grade_section = any(
                    		descriptor.always_recalculate_grades for descriptor in section['xmoduledescriptors']
                	)

                	if not should_grade_section:
                    		should_grade_section = any(
                        		descriptor.location.to_deprecated_string() in submissions_scores
                        		for descriptor in section['xmoduledescriptors']
                    		)

                	if not should_grade_section:
                    		should_grade_section = any(
                        		descriptor.location in scores_client
                        		for descriptor in section['xmoduledescriptors']
                    		)
			if should_grade_section:
                    		scores = []
				def create_module(descriptor):
                        		'''creates an XModule instance given a descriptor'''
                        		# TODO: We need the request to pass into here. If we could forego that, our arguments
                       		        # would be simpler
                        		return get_module_for_descriptor(
                            			student, request, descriptor, field_data_cache, course.id, course=course
                       		        )
				descendants = yield_dynamic_descriptor_descendants(section_descriptor, student.id, create_module)
                    		for module_descriptor in descendants:
                        		user_access = has_access(
                            			student, 'load', module_descriptor, module_descriptor.location.course_key
                        		)
                        	if not user_access:
                           		 continue

                        	(correct, total) = get_score(
                           		 		student,
                            				module_descriptor,
                            				create_module,
                            				scores_client,
                            				submissions_scores,
                            				max_scores_cache,
                        				)
				if correct is None and total is None:
                            		continue

                       	        if settings.GENERATE_PROFILE_SCORES:    # for debugging!
                            		if total > 1:
                                		correct = random.randrange(max(total - 2, 1), total + 1)
                            		else:
                              		  correct = total

                        	graded = module_descriptor.graded
                        	if not total > 0:
                            		# We simply cannot grade a problem that is 12/0, because we might need it as a percentage
                            		graded = False

                        	scores.append(
                            		Score(
                                		correct,
                                		total,
                                		graded,
                               			None,
                                		module_descriptor.location
                            		)
                        	)
				
				__, graded_total = graders.aggregate_scores(scores, section_name)
                    		if keep_raw_scores:
                        		raw_scores += scores
			else:
                    		graded_total = Score(0.0, 1.0, True, section_name, None)
			if graded_total.possible > 0:
                    		format_scores.append(graded_total)
                	else:
                    		log.info(
                       			 "Unable to grade a section with a total possible score of zero. " +
                        		 str(section_descriptor.location)
                    			)
		totaled_scores[section_format] = format_scores
	course.set_grading_policy(course.grading_policy)
        grade_summary = course.grader.grade(totaled_scores, generate_random_scores=settings.GENERATE_PROFILE_SCORES)
	

	grade_summary['percent'] = round(grade_summary['percent'] * 100 + 0.05) / 100

        letter_grade = grade_for_percentage(course.grade_cutoffs, grade_summary['percent'])
        grade_summary['grade'] = letter_grade
	print "totaled_scores=====================",totaled_scores
        grade_summary['totaled_scores'] = totaled_scores   # make this available, eg for instructor download & debugging
        #keep_raw_scores = False
	if keep_raw_scores:
            # way to get all RAW scores out to instructor
            # so grader can be double-checked
            grade_summary['raw_scores'] = raw_scores

	context = {
            'passed': grade_summary,
            'show_generate_cert_btn': show_generate_cert_btn,
        }

        if show_generate_cert_btn:
            cert_status = certs_api.certificate_downloadable_status(student, course_key)
            context.update(cert_status)
        # showing the certificate web view button if feature flags are enabled.
        if certs_api.has_html_certificates_enabled(course_key, course):
            if certs_api.get_active_web_certificate(course) is not None:
                context.update({
                    'show_cert_web_view': True,
                    'cert_web_view_url': certs_api.get_certificate_url(course_id=course_key, uuid=cert_status['uuid']),
                })
            else:
                context.update({
                    'is_downloadable': False,
                    'is_generating': True,
                    'download_url': None
                })

        return context


    # TO-DO: change this to create the scenarios you'd like to see in the
    # workbench while developing your XBlock.
    @staticmethod
    def workbench_scenarios():
        """A canned scenario for display in the workbench."""
        return [
            ("CertRequestXBlock",
             """<cert_request/>
             """),
            ("Multiple CertRequestXBlock",
             """<vertical_demo>
                <cert_request/>
                <cert_request/>
                <cert_request/>
                </vertical_demo>
             """),
        ]

def grade_for_percentage(grade_cutoffs, percentage):
    """
    Returns a letter grade as defined in grading_policy (e.g. 'A' 'B' 'C' for 6.002x) or None.

    Arguments
    - grade_cutoffs is a dictionary mapping a grade to the lowest
        possible percentage to earn that grade.
    - percentage is the final percent across all problems in a course
    """

    letter_grade = None

    # Possible grades, sorted in descending order of score
    descending_grades = sorted(grade_cutoffs, key=lambda x: grade_cutoffs[x], reverse=True)
    for possible_grade in descending_grades:
        if percentage >= grade_cutoffs[possible_grade]:
            letter_grade = possible_grade
            break

    return letter_grade
